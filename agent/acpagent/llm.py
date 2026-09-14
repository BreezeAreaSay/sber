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

MIN_CALL_TIMEOUT = 15.0
MAX_CALL_TIMEOUT = 240.0
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
            data = json.dumps(body).encode("utf-8")
            req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
            started = time.monotonic()
            self.calls += 1
            try:
                with urllib.request.urlopen(req, timeout=max(MIN_CALL_TIMEOUT, timeout)) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                return self._parse(raw)
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
                if spent >= timeout * 0.9:
                    # The generation itself outran the timeout. Repeating it verbatim
                    # buys the same result; shorten the output cap once, then give up.
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

    def _parse(self, raw: str) -> ChatResult:
        data = json.loads(raw)
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
        if not ui:
            ui = estimate_tokens(json.dumps(data.get("_request", "")))  # unknown: 0
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
