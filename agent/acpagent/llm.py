"""Minimal, dependency-free client for one OpenAI-compatible chat endpoint.

Only the standard library is used on purpose: the runtime image is fixed and nothing
can be installed, so a missing package would silently turn every task into a 0.

Everything defensive here exists because the model is small and the server unknown:
it may reject tool schemas, reject unknown request fields, stream reasoning into a
side field, or spend the whole budget thinking. Each case has a measured response.
"""

import json
import re
import socket
import time
import urllib.error
import urllib.request

import os

MIN_CALL_TIMEOUT = 15.0
MAX_CALL_TIMEOUT = 300.0
# Streaming reads: a model that produces nothing for this long is stuck (a long prompt
# still has to be processed before the first token, so this is not tiny).
IDLE_TIMEOUT = float(os.environ.get("LOCAL_AGENT_IDLE_TIMEOUT") or 150.0)
MIN_USEFUL_CALL_SEC = 6.0
# Seconds held back from the last call so the finaliser can still write a deliverable
# inside the soft deadline.
RESERVE_SEC = 4.0

DEFAULT_MAX_TOKENS = 4096
ESCALATED_MAX_TOKENS = 8192

_NO_TOOLS_SIGNS = (
    "does not support tools", "tools is not supported", "tool_choice", "'tools'",
    "\"tools\"", "function calling", "tool calling", "tool use", "tools are not",
    "unsupported parameter: tools", "tools field",
)
_UNKNOWN_FIELD_SIGNS = (
    "chat_template_kwargs", "extra fields", "unexpected keyword", "unrecognized",
    "unknown field", "additional properties", "not permitted", "unknown parameter",
    "unrecognized request argument",
)
_CONTEXT_SIGNS = (
    "context length", "context_length", "maximum context", "context size",
    "too many tokens", "exceeds the available context", "reduce the length",
    "prompt is too long", "input is too long", "max_tokens", "n_ctx", "exceed",
)


class BudgetExceeded(Exception):
    """No further useful call can be made: the deadline or the token cap is gone."""


class ContextTooLong(Exception):
    """The server rejected the transcript as too long; the caller must trim it."""


class ToolCall:
    __slots__ = ("id", "name", "arguments", "recovered")

    def __init__(self, id, name, arguments, recovered=False):
        self.id = id
        self.name = name
        self.arguments = arguments
        self.recovered = recovered


class ChatResult:
    __slots__ = ("text", "tool_calls", "finish", "usage_in", "usage_out", "reasoning")

    def __init__(self, text="", tool_calls=None, finish="", usage_in=0, usage_out=0, reasoning=""):
        self.text = text
        self.tool_calls = tool_calls or []
        self.finish = finish
        self.usage_in = usage_in
        self.usage_out = usage_out
        self.reasoning = reasoning


class LLM:
    def __init__(self, base_url, api_key, model, deadline_ts, token_budget, log=print):
        url = (base_url or "http://127.0.0.1:8000/v1").rstrip("/")
        if not url.endswith("/chat/completions"):
            url = url + "/chat/completions"
        self.url = url
        self.models_url = url[: -len("/chat/completions")] + "/models"
        self.api_key = api_key or "local"
        self.model = model
        self.deadline_ts = deadline_ts
        self.token_budget = token_budget
        self.log = log
        self.tokens_used = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.calls = 0
        self.failures = 0
        self.supports_tools = True
        # Thinking off by default: on a small model it multiplies latency and tokens
        # without a matching gain on tool-driven work. Dropped if the server objects.
        self.extra = {"chat_template_kwargs": {"enable_thinking": False}}
        self.max_tokens = DEFAULT_MAX_TOKENS
        self.temperature = 0.0
        self.last_error = ""
        # Streaming lets a slow but progressing generation finish, while a hung one is
        # cut by the idle timeout. Switched off if the server cannot stream.
        self.stream = os.environ.get("LOCAL_AGENT_NO_STREAM", "") == ""
        self._stream_failures = 0
        self._stream_options = True

    # ---- budget -----------------------------------------------------------------

    def remaining(self) -> float:
        return self.deadline_ts - time.monotonic()

    def exhausted(self, need: int = 1500) -> bool:
        return self.remaining() < MIN_USEFUL_CALL_SEC + RESERVE_SEC or (
            self.tokens_used + need > self.token_budget
        )

    def _timeout(self) -> float:
        rem = self.remaining() - RESERVE_SEC
        return max(0.0, min(MAX_CALL_TIMEOUT, rem))

    # ---- discovery ---------------------------------------------------------------

    def discover_model(self) -> str:
        """Resolve a model id when none was configured, via GET /models."""
        if self.model:
            return self.model
        try:
            req = urllib.request.Request(self.models_url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
            items = data.get("data") or data.get("models") or []
            for it in items:
                mid = it.get("id") if isinstance(it, dict) else None
                if mid:
                    self.model = mid
                    self.log(f"[llm] discovered model id: {mid}")
                    return mid
        except Exception as exc:  # noqa: BLE001
            self.log(f"[llm] model discovery failed: {exc}"[:200])
        self.model = self.model or "default"
        return self.model

    # ---- request -----------------------------------------------------------------

    def _headers(self):
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }

    def _body(self, messages, tools, temperature, max_tokens):
        body = {
            "model": self.model or "default",
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }
        if tools and self.supports_tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        body.update(self.extra)
        return body

    def chat(self, messages, tools=None, temperature=None, max_tokens=None) -> ChatResult:
        temp = self.temperature if temperature is None else temperature
        mt = max_tokens or self.max_tokens
        if self.tokens_used >= self.token_budget:
            raise BudgetExceeded(f"token budget spent ({self.tokens_used}/{self.token_budget})")
        attempts = 0
        backoff = 1.0
        while attempts < 5:
            attempts += 1
            timeout = self._timeout()
            if timeout < MIN_USEFUL_CALL_SEC:
                raise BudgetExceeded("not enough time left for another model call")
            body = self._body(messages, tools, temp, mt)
            started = time.monotonic()
            self.calls += 1
            try:
                if self.stream:
                    data = self._request_stream(body, timeout)
                else:
                    data = self._request_plain(body, timeout)
                return self._parse(data, messages)
            except urllib.error.HTTPError as exc:
                self.failures += 1
                try:
                    err_text = exc.read().decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    err_text = ""
                low = (err_text or str(exc)).lower()
                self.last_error = f"HTTP {exc.code}: {err_text[:300]}"
                self.log(f"[llm] call failed: {self.last_error}"[:400])
                if exc.code in (400, 404, 422):
                    if self.stream and self._stream_options and "stream_options" in low:
                        self.log("[llm] endpoint rejects stream_options; retrying without it")
                        self._stream_options = False
                        continue
                    if self.stream and ("stream" in low):
                        self.log("[llm] endpoint rejects streaming; retrying without it")
                        self.stream = False
                        continue
                    if self.extra and any(s in low for s in _UNKNOWN_FIELD_SIGNS):
                        self.log("[llm] endpoint rejects extra fields; retrying without them")
                        self.extra = {}
                        continue
                    if tools and self.supports_tools and any(s in low for s in _NO_TOOLS_SIGNS):
                        self.log("[llm] endpoint rejects tools; switching to text protocol")
                        self.supports_tools = False
                        raise ToolsUnsupported()
                    if any(s in low for s in _CONTEXT_SIGNS):
                        raise ContextTooLong(err_text[:200])
                    if self.extra:
                        # Unknown 400: the extra field is the most likely culprit.
                        self.extra = {}
                        continue
                    raise BudgetExceeded(self.last_error)
                if exc.code in (401, 403):
                    raise BudgetExceeded(self.last_error)
                # 429 / 5xx: transient
                time.sleep(min(backoff, 5.0))
                backoff *= 2
                continue
            except (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
                self.failures += 1
                spent = time.monotonic() - started
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.log(f"[llm] call failed after {spent:.0f}s: {self.last_error}"[:300])
                if isinstance(exc, GenerationTooLong):
                    raise BudgetExceeded(str(exc))
                if spent >= timeout * 0.9 or isinstance(exc, (socket.timeout, TimeoutError)):
                    if self.stream and self._stream_failures == 0 and self.remaining() > 60:
                        # A stream that stalled once may be a server that buffers the whole
                        # reply; try the plain request before giving up on the call.
                        self._stream_failures += 1
                        self.stream = False
                        self.log("[llm] stream stalled; retrying without streaming")
                        continue
                    if mt > 1536 and self.remaining() > 60:
                        mt = max(1536, mt // 2)
                        continue
                    raise BudgetExceeded("model call timed out")
                if self.remaining() < MIN_USEFUL_CALL_SEC + RESERVE_SEC:
                    raise BudgetExceeded("deadline reached during retry")
                time.sleep(min(backoff, 5.0))
                backoff *= 2
                continue
            except ValueError as exc:
                self.failures += 1
                self.last_error = f"bad response: {exc}"
                self.log(f"[llm] {self.last_error}"[:300])
                time.sleep(1.0)
                continue
        raise BudgetExceeded(f"model call failed repeatedly: {self.last_error}")

    def _parse(self, data, messages=None) -> ChatResult:
        if isinstance(data, (str, bytes)):
            data = json.loads(data)
        if not isinstance(data, dict) or "choices" not in data:
            err = data.get("error") if isinstance(data, dict) else None
            raise ValueError(f"no choices in response: {str(err or data)[:200]}")
        choices = data.get("choices") or []
        if not choices:
            raise ValueError("empty choices")
        choice = choices[0]
        msg = choice.get("message") or {}
        text = msg.get("content")
        if isinstance(text, list):  # some servers return content parts
            text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
        text = text or ""
        reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
        finish = choice.get("finish_reason") or ""
        usage = data.get("usage") or {}
        ui = int(usage.get("prompt_tokens") or 0)
        uo = int(usage.get("completion_tokens") or 0)
        if not ui and messages is not None:
            ui = sum(estimate_tokens(m.get("content") or "") for m in messages) + 400
        if not uo:
            uo = estimate_tokens(text) + sum(estimate_tokens(json.dumps(tc)) for tc in (msg.get("tool_calls") or []))
        self.prompt_tokens += ui
        self.completion_tokens += uo
        self.tokens_used += ui + uo
        calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            name = fn.get("name") or tc.get("name") or ""
            args = parse_arguments(fn.get("arguments", tc.get("arguments")))
            if not name:
                continue
            calls.append(ToolCall(tc.get("id") or f"call_{self.calls}_{i}", name, args))
        # A model cut off mid-thought returns nothing usable; raise the cap so the next
        # turn can finish. Thinking text is kept only as a last resort for recovery.
        if finish == "length" and not text.strip() and not calls:
            if self.max_tokens < ESCALATED_MAX_TOKENS:
                self.max_tokens = ESCALATED_MAX_TOKENS
                self.log(f"[llm] empty cut-off reply; output cap raised to {ESCALATED_MAX_TOKENS}")
            if reasoning:
                text = ""
        return ChatResult(text=text, tool_calls=calls, finish=finish, usage_in=ui, usage_out=uo,
                          reasoning=str(reasoning or ""))


class GenerationTooLong(Exception):
    """The streamed generation ran past the deadline."""


def _request_plain(self, body, timeout):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
    with urllib.request.urlopen(req, timeout=max(MIN_CALL_TIMEOUT, timeout)) as resp:
        return resp.read().decode("utf-8", "replace")


def _request_stream(self, body, timeout):
    """POST with stream=True and assemble the SSE chunks into one response object."""
    body = dict(body)
    body["stream"] = True
    if self._stream_options:
        body["stream_options"] = {"include_usage": True}
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
    idle = max(MIN_CALL_TIMEOUT, min(IDLE_TIMEOUT, timeout))
    started = time.monotonic()
    resp = urllib.request.urlopen(req, timeout=idle)
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/event-stream" not in ctype:
        raw = resp.read().decode("utf-8", "replace")
        try:
            return json.loads(raw)
        except ValueError:
            pass
        # Some servers stream without the SSE content type; fall through and parse lines.
        lines = raw.splitlines()
    else:
        lines = resp
    text, reasoning, calls = [], [], {}
    finish, usage = None, None
    try:
        for raw_line in lines:
            if time.monotonic() - started > timeout:
                raise GenerationTooLong("generation ran past the deadline")
            line = raw_line.decode("utf-8", "replace") if isinstance(raw_line, bytes) else raw_line
            line = line.strip()
            if not line or not line.startswith("data:"):
                if line.startswith("{") and "error" in line:
                    raise ValueError(line[:300])
                continue
            payload = line[5:].strip()
            if payload == "[DONE]":
                break
            try:
                chunk = json.loads(payload)
            except ValueError:
                continue
            if not isinstance(chunk, dict):
                continue
            if chunk.get("error") and not chunk.get("choices"):
                raise ValueError(str(chunk["error"])[:300])
            if chunk.get("usage"):
                usage = chunk["usage"]
            for ch in chunk.get("choices") or []:
                delta = ch.get("delta") or {}
                if delta.get("content"):
                    text.append(delta["content"])
                rc = delta.get("reasoning_content") or delta.get("reasoning")
                if rc:
                    reasoning.append(rc)
                for tc in delta.get("tool_calls") or []:
                    idx = tc.get("index", 0) if isinstance(tc.get("index", 0), int) else 0
                    slot = calls.setdefault(idx, {"id": None, "name": "", "arguments": ""})
                    if tc.get("id"):
                        slot["id"] = tc["id"]
                    fn = tc.get("function") or {}
                    name = fn.get("name")
                    if name and name != slot["name"]:
                        slot["name"] = name if not slot["name"] else slot["name"] + name
                    args = fn.get("arguments")
                    if args:
                        slot["arguments"] += args if isinstance(args, str) else json.dumps(args)
                if ch.get("finish_reason"):
                    finish = ch["finish_reason"]
    finally:
        try:
            resp.close()
        except Exception:  # noqa: BLE001
            pass
    message = {"content": "".join(text), "reasoning_content": "".join(reasoning)}
    if calls:
        message["tool_calls"] = [
            {"id": slot["id"] or f"call_{self.calls}_{i}", "type": "function",
             "function": {"name": slot["name"], "arguments": slot["arguments"]}}
            for i, slot in sorted(calls.items())
        ]
    return {"choices": [{"message": message, "finish_reason": finish or ("tool_calls" if calls else "stop")}],
            "usage": usage or {}}


LLM._request_plain = _request_plain
LLM._request_stream = _request_stream


class ToolsUnsupported(Exception):
    """Raised once when the endpoint refuses tool schemas; the loop switches protocol."""


def estimate_tokens(text) -> int:
    if not text:
        return 0
    return max(1, len(str(text)) // 4)


_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")


def parse_arguments(raw):
    """Turn whatever the model put in `function.arguments` into a dict."""
    if isinstance(raw, dict):
        return raw
    if raw is None:
        return {}
    text = str(raw).strip()
    if not text:
        return {}
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            text = text.split("\n", 1)[1]
        text = text.rstrip("`").strip()
    for candidate in (text, _TRAILING_COMMA_RE.sub(r"\1", text)):
        try:
            data = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(data, dict):
            return data
        if isinstance(data, str):
            try:
                nested = json.loads(data)
                if isinstance(nested, dict):
                    return nested
            except (ValueError, TypeError):
                pass
            return {"_raw": data}
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        try:
            data = json.loads(_TRAILING_COMMA_RE.sub(r"\1", text[start:end + 1]))
            if isinstance(data, dict):
                return data
        except (ValueError, TypeError):
            pass
    return {"_raw": text}
