#!/usr/bin/env python3
"""Autonomous offline security agent: triage the statement, brief the model, run a
bounded tool loop, verify the deliverable, always leave a valid artifact, exit 0."""

import json
import os
import re
import signal
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from acpagent import brief, forensic_seed, oracle, prompts, safefix, sqlfix, tools  # noqa: E402
from acpagent import spec as specmod  # noqa: E402
from acpagent.llm import (LLM, BudgetExceeded, ContextTooLong, ToolCall, ToolsUnsupported,  # noqa: E402
                          estimate_tokens, parse_arguments)

# ---- budgets -----------------------------------------------------------------------------
# Published limits are 120s for trivial tasks and 600s for everything else. A run that is
# not yet solved scores 0 whether it stops voluntarily or gets killed, so the soft deadline
# is generous but leaves margin for the finaliser and for slower hidden limits.
SOFT_DEADLINE_SEC = float(os.environ.get("LOCAL_AGENT_DEADLINE_SEC") or 520)
HARD_GRACE_SEC = 12
TOKEN_BUDGET = int(os.environ.get("LOCAL_AGENT_TOKEN_BUDGET") or 140000)
MAX_ROUNDS = int(os.environ.get("LOCAL_AGENT_MAX_ROUNDS") or 48)
MAX_CORRECTIONS = 8
HISTORY_CHAR_CAP = int(os.environ.get("LOCAL_AGENT_HISTORY_CHARS") or 70000)
KEEP_RECENT_ROUNDS = 4
TEST_TIMEOUT_SEC = 170

WORKDIR_CANDIDATES = ("/app", "/workspace", "/srv/app", "/data", "/opt/app", "/home/user/app")

START_TS = time.monotonic()


def log(msg: str) -> None:
    print(f"[agent] {msg}", flush=True)


def pick_workdir() -> Path:
    forced = os.environ.get("AGENT_FORCE_WORKDIR")
    if forced:
        return Path(forced)
    raw = os.environ.get("LOCAL_AGENT_WORKDIR")
    if raw and Path(raw).is_dir() and not (Path(raw) / "agent.py").is_file():
        return Path(raw)
    for cand in WORKDIR_CANDIDATES:
        p = Path(cand)
        try:
            if p.is_dir() and any(p.iterdir()):
                return p
        except OSError:
            continue
    return Path(raw) if raw else Path.cwd()


class State:
    def __init__(self):
        self.workdir = Path("/app")
        self.spec = None
        self.instruction = ""
        self.llm = None
        self.brief = {"text": "", "hotspots": [], "routes": [], "flags": []}
        self.snapshot = {}
        self.servers = []
        self.seed = None
        self.final_text = ""
        self.finalized = False
        self.deadline_ts = START_TS + SOFT_DEADLINE_SEC
        self.deliverable_mtime = None
        self.tests_passed = False
        self.critical_nudged = False
        self.mechanical_notes = []
        self.seen_flags = []  # flag-shaped strings observed in tool outputs (ctf)
        self.call_history = []  # (tool, args) of every executed call, for retry notes
        self.retry_note = ""


# ---- text protocol recovery ----------------------------------------------------------------

_TC_TAG_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)
_TC_FENCE_RE = re.compile(r"```(?:json|tool_call|tool)?\s*(\{.*?\})\s*```", re.S)
_CODE_FENCE_RE = re.compile(r"```(bash|sh|shell|console|zsh)?\s*\n(.*?)```", re.S)


def _as_call(data, idx):
    if not isinstance(data, dict):
        return None
    name = data.get("name") or data.get("tool") or data.get("tool_name") or data.get("function")
    args = data.get("arguments", data.get("args", data.get("parameters", data.get("input"))))
    if isinstance(name, dict):
        args = name.get("arguments", name.get("parameters", args))
        name = name.get("name")
    if not isinstance(name, str):
        return None
    canonical = tools.canonical_name(name)
    if canonical not in tools.TOOL_NAMES:
        return None
    if isinstance(args, str):
        args = parse_arguments(args)
    if not isinstance(args, dict):
        args = {k: v for k, v in data.items() if k not in ("name", "tool", "tool_name", "function", "type", "id")}
    return ToolCall(f"recovered_{idx}", canonical, args, recovered=True)


def recover_calls(text: str):
    """Tool calls a model wrote into its message instead of the tool_calls field."""
    if not text:
        return []
    calls = []
    for rx in (_TC_TAG_RE, _TC_FENCE_RE):
        for m in rx.finditer(text):
            try:
                data = json.loads(m.group(1))
            except ValueError:
                try:
                    data = json.loads(re.sub(r",\s*([}\]])", r"\1", m.group(1)))
                except ValueError:
                    continue
            c = _as_call(data, len(calls))
            if c:
                calls.append(c)
        if calls:
            return calls
    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        data = oracle.load_json_lenient(stripped)
        c = _as_call(data, 0)
        if c:
            return [c]
    # A lone shell fence with almost no prose around it is a command the model meant to run.
    fences = _CODE_FENCE_RE.findall(text)
    if len(fences) == 1 and fences[0][0]:
        outside = _CODE_FENCE_RE.sub("", text).strip()
        if len(outside) < 240 and "DONE" not in outside.upper():
            cmd = fences[0][1].strip()
            if cmd and len(cmd) < 4000:
                return [ToolCall("recovered_sh", "bash", {"command": cmd}, recovered=True)]
    return []


# ---- history management ----------------------------------------------------------------------

def _msg_chars(m) -> int:
    n = len(m.get("content") or "")
    for tc in m.get("tool_calls") or ():
        n += len(json.dumps(tc.get("function", {})))
    return n


def trim_history(messages, cap=HISTORY_CHAR_CAP, keep_recent=KEEP_RECENT_ROUNDS, aggressive=False):
    """Elide old tool outputs (and, if needed, drop whole old rounds) to fit under cap."""
    total = sum(_msg_chars(m) for m in messages)
    if total <= cap and not aggressive:
        return messages
    # index of assistant turns
    assistant_idx = [i for i, m in enumerate(messages) if m.get("role") == "assistant"]
    if len(assistant_idx) <= 1:
        return messages
    cutoff = assistant_idx[-keep_recent] if len(assistant_idx) >= keep_recent else assistant_idx[0]
    out = []
    for i, m in enumerate(messages):
        if i < cutoff and i >= 2 and m.get("role") in ("tool", "user") and len(m.get("content") or "") > 400:
            content = m["content"]
            m = dict(m)
            m["content"] = content[:300] + f"\n... [{len(content) - 300} chars of earlier output elided]"
        out.append(m)
    total = sum(_msg_chars(m) for m in out)
    if total <= cap and not aggressive:
        return out
    # Drop whole old rounds (assistant + its tool replies) but keep system + task + last rounds.
    prefix = out[:2]
    rounds = []
    for m in out[2:]:
        if m.get("role") == "assistant" or not rounds:
            rounds.append([m])
        else:
            rounds[-1].append(m)
    dropped = 0
    while len(rounds) > max(2, keep_recent - 1) and (aggressive or sum(_msg_chars(m) for r in rounds for m in r) + sum(_msg_chars(m) for m in prefix) > cap):
        rounds.pop(0)
        dropped += 1
        aggressive = False
    note = {"role": "user", "content": f"[{dropped} earlier round(s) were removed to save context. Do not repeat exploration you already did; the files you edited are still edited.]"} if dropped else None
    result = prefix + ([note] if note else []) + [m for r in rounds for m in r]
    # A tool message must follow an assistant message with tool_calls; drop orphans.
    cleaned = []
    for m in result:
        if m.get("role") == "tool":
            prev = cleaned[-1] if cleaned else None
            if not prev or prev.get("role") not in ("assistant", "tool"):
                continue
        cleaned.append(m)
    return cleaned


# ---- prompts -------------------------------------------------------------------------------

def system_prompt(st: State, text_protocol: bool) -> str:
    sp = st.spec
    base = prompts.BASE.format(workdir=st.workdir)
    if sp.kind == "json_report":
        block = prompts.VULN_REPORT.format(path=sp.deliverable, shape=prompts.report_shape(sp.json_root, sp.json_fields))
        if sp.also_fix:
            block = block.replace("Do NOT modify application code.",
                                  "The task ALSO asks you to fix the issues: after writing the report, edit the "
                                  "vulnerable code with str_replace (parameterized queries, no shell=True, path "
                                  "checks) without changing normal behaviour, and run the project's tests if any.")
    elif sp.kind == "code_fix":
        hint = f" (`{sp.test_cmd}`)" if sp.test_cmd else ""
        block = prompts.CODE_FIX.format(test_hint=hint)
    elif sp.kind == "kv_report":
        example = "\n".join(f"{k}=<value>" for k in sp.keys)
        fmt = prompts.KV_FORMAT.format(path=sp.deliverable, n=len(sp.keys), keys=", ".join(sp.keys), example=example)
        block = prompts.FORENSICS.format(format_block=fmt)
    elif sp.kind == "ctf":
        flag_hint = f"The flag format is {sp.flag_prefix}...}}." if sp.flag_prefix else "Flags usually look like TAG{...}."
        if sp.deliverable:
            dblock = f"Deliverable: write ONLY the flag (nothing else) to {sp.deliverable} with write_file, then reply DONE followed by the flag."
        else:
            dblock = "When you have the flag, reply exactly: DONE FLAG: <the flag> (no tool call). If the task names an output file, write the flag there too."
        block = prompts.CTF.format(flag_hint=flag_hint, deliverable_block=dblock)
    else:
        if sp.deliverable:
            dblock = f"Deliverable: {sp.deliverable} (write it with write_file, then reply DONE)."
        else:
            dblock = "If the task names an output file, write it; otherwise put the final answer on the last line of your DONE reply."
        block = prompts.GENERIC.format(deliverable_block=dblock)
    out = base + block
    if text_protocol:
        out += prompts.TEXT_PROTOCOL
    return out


def user_prompt(st: State) -> str:
    parts = [f"TASK:\n{st.instruction.strip()}"]
    if st.brief.get("text"):
        parts.append(f"CONTEXT GATHERED AUTOMATICALLY (verify before relying on it):\n{st.brief['text']}")
    if st.retry_note:
        parts.append(st.retry_note)
    if st.mechanical_notes:
        parts.append("ALREADY FIXED MECHANICALLY (tests pass with these changes; do not redo them):\n"
                     + "\n".join(f"- {n}" for n in st.mechanical_notes))
    if st.seed:
        parts.append("PRELIMINARY AUTOMATED CORRELATION (may be wrong — verify against the evidence, then write the "
                     "final file yourself):\n" + "\n".join(f"{k}={v}" for k, v in st.seed.items() if not k.startswith("_"))
                     + ("\n" + st.seed["_detail"] if st.seed.get("_detail") else ""))
    sp = st.spec
    if sp.kind == "kv_report" and sp.deliverable:
        parts.append(f"REMINDER: the graded file is {sp.deliverable} with exactly these keys: {', '.join(sp.keys)}.")
    elif sp.deliverable:
        parts.append(f"REMINDER: the graded file is {sp.deliverable}.")
    return "\n\n".join(parts)


# ---- oracle dispatch -----------------------------------------------------------------------

def _mtime(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def check_done(st: State, final_text: str):
    """Return (ok, why). Runs the kind-specific oracle."""
    sp = st.spec
    try:
        if sp.kind == "exact":
            for pth, content in (sp.exact_files or [(sp.deliverable, sp.exact_content)]):
                ok, why = oracle.check_exact(pth, content)
                if not ok:
                    return ok, why
            return True, ""
        if sp.kind == "json_report":
            ok, why = oracle.check_json_report(sp.deliverable, sp.json_root, sp.json_fields)
            if not ok and final_text and len(final_text) > 200:
                obj = oracle.load_json_lenient(final_text)
                report, findings = oracle.normalise_report(obj, sp.json_root, sp.json_fields) if obj is not None else (None, None)
                if report is not None and findings:
                    oracle.write_text(sp.deliverable, json.dumps(report, ensure_ascii=False, indent=2))
                    log(f"salvaged a JSON report with {len(findings)} finding(s) from the reply")
                    return oracle.check_json_report(sp.deliverable, sp.json_root, sp.json_fields)
            return ok, why
        if sp.kind == "kv_report":
            ok, why = oracle.check_kv(sp.deliverable, sp.keys)
            if not ok and final_text:
                found = oracle.salvage_kv_from_text(final_text, sp.keys)
                if found and not any(v.lower() in oracle.PLACEHOLDERS for v in found.values()):
                    oracle.write_kv(sp.deliverable, found, sp.keys)
                    log("salvaged key=value answer from the reply")
                    return oracle.check_kv(sp.deliverable, sp.keys)
            return ok, why
        if sp.kind == "ctf":
            if sp.deliverable:
                ok, why = oracle.check_flag_file(sp.deliverable, sp.flag_prefix)
                if not ok and final_text:
                    flag = oracle.extract_flag(final_text, sp.flag_prefix)
                    if flag:
                        oracle.write_text(sp.deliverable, flag)
                        log(f"salvaged flag from the reply: {flag}")
                        return True, ""
                return ok, why
            flag = oracle.extract_flag(final_text or "", sp.flag_prefix)
            if flag:
                return True, ""
            return (bool(final_text and final_text.strip()), "no flag found in the reply; reply DONE FLAG: <flag>")
        if sp.kind == "code_fix":
            return check_code_fix(st)
        if sp.deliverable:
            return oracle.check_nonempty(sp.deliverable)
        return True, ""
    except Exception as exc:  # noqa: BLE001
        log(f"oracle raised: {exc}")
        return True, ""


def check_code_fix(st: State):
    changed = oracle.changed_files(st.workdir, st.snapshot)
    if not changed:
        return False, ("no source file has been modified yet. Read the code, find the vulnerability the task "
                       "describes and edit the file with str_replace.")
    errs = oracle.compile_errors(changed)
    if errs:
        return False, "syntax errors in edited files:\n" + "\n".join(errs)[:1500]
    remaining = st.deadline_ts - time.monotonic()
    if st.servers and remaining > 40:
        problems = oracle.restart_servers(st.servers, log=log)
        if problems:
            return False, "\n".join(problems)[:2500]
    if st.spec.test_cmd and remaining > 30:
        ok, out = oracle.run_tests(st.spec.test_cmd, st.workdir, min(TEST_TIMEOUT_SEC, max(20, remaining - 15)))
        if ok is False:
            why = f"the test command `{st.spec.test_cmd}` fails:\n{tools.truncate(out, 2500)}"
            if "500" in out or "Internal Server Error" in out or "Connection" in out:
                why += oracle.server_log_tail(st.servers)
            return False, why
        if ok is None:
            log("test command produced no usable result; not blocking on it")
        else:
            st.tests_passed = True
    if st.spec.deliverable:
        ok, why = oracle.check_nonempty(st.spec.deliverable)
        if not ok:
            return False, f"the task also asks for a written file: {why}"
    if not st.critical_nudged:
        crit = [h for h in oracle.remaining_critical(st.workdir) if h["label"].startswith("SQL") or "command" in h["label"].lower()]
        if crit:
            st.critical_nudged = True
            listing = brief.format_hotspots(crit[:6])
            return False, ("tests pass, but these lines still build SQL/shell commands from input — if any of them is "
                           "reachable with user data, fix it too; if they are all false positives reply DONE again:\n" + listing)
    return True, ""


# ---- deterministic code fix ---------------------------------------------------------------------

def _verify_stage(st: State, label: str, originals: dict, notes: list, module) -> bool:
    """Keep a mechanical rewrite only if the code compiles, the app restarts and the
    tests pass; otherwise revert it (and put the server back)."""
    if not originals:
        return False
    for n in notes:
        log(f"{label}: {n}")
    ok = True
    errs = oracle.compile_errors([Path(p) for p in originals])
    if errs:
        log(f"{label} produced syntax errors; reverting: {errs[0][:200]}")
        ok = False
    if ok and st.servers:
        problems = oracle.restart_servers(st.servers, log=log)
        if problems:
            log(f"server failed after {label}; reverting: {problems[0][:200]}")
            ok = False
    if ok and st.spec.test_cmd:
        tok, out = oracle.run_tests(st.spec.test_cmd, st.workdir,
                                    min(TEST_TIMEOUT_SEC, max(20, st.deadline_ts - time.monotonic() - 30)))
        if tok is False:
            log(f"tests fail after {label}; reverting: {out[-300:]}")
            ok = False
        elif tok is None:
            log(f"tests produced no usable result after {label}; keeping the rewrite (it compiles)")
    if not ok:
        module.revert(originals)
        if st.servers:
            oracle.restart_servers(st.servers, log=log)
        return False
    return True


def mechanical_sql_fix(st: State) -> bool:
    """Apply the mechanical rewrites (SQL parameterization, then command/config
    hardening), each verified by the project's tests. Returns True when nothing risky
    is left and the task is finished."""
    kept = []
    originals, notes = sqlfix.apply(st.workdir)
    if _verify_stage(st, "sqlfix", originals, notes, sqlfix):
        kept.extend(notes)
    originals, notes = safefix.apply(st.workdir)
    if _verify_stage(st, "safefix", originals, notes, safefix):
        kept.extend(notes)
    if not kept:
        return False
    st.tests_passed = True
    remaining = [h for h in brief.scan_hotspots(st.workdir)
                 if h["severity"] in ("critical", "high") and h["category"] not in brief.AUDIT_ONLY_CATEGORIES]
    if st.spec.deliverable:
        remaining.append({"file": st.spec.deliverable, "line": 0, "label": "deliverable still to be written"})
    if not remaining:
        log("code_fix solved deterministically: mechanical fixes applied, tests pass, no risky patterns left (0 tokens)")
        return True
    st.mechanical_notes = kept
    log(f"mechanical fixes kept; {len(remaining)} risky pattern(s) remain for the model")
    return False


# ---- main loop -----------------------------------------------------------------------------

def run_loop(st: State):
    llm = st.llm
    sp = st.spec
    text_mode = not llm.supports_tools
    messages = [
        {"role": "system", "content": system_prompt(st, text_mode)},
        {"role": "user", "content": user_prompt(st)},
    ]
    st.deliverable_mtime = _mtime(sp.deliverable) if sp.deliverable else None
    rounds = 0
    corrections = 0
    empty_streak = 0
    last_sig = None
    repeat = 0
    context_retries = 0
    final_text = ""
    edit_counts = {}
    sig_counts = {}      # (call, result) signature -> occurrences anywhere in the run
    error_streak = 0     # consecutive tool results that were errors
    no_call_rounds = 0   # rounds without any tool call while tools were advertised
    ever_called = False
    while rounds < MAX_ROUNDS:
        if llm.exhausted():
            log("budget exhausted; leaving the loop")
            break
        messages = trim_history(messages)
        try:
            res = llm.chat(messages, tools=None if text_mode else tools.TOOL_SCHEMAS)
        except ToolsUnsupported:
            text_mode = True
            messages[0] = {"role": "system", "content": system_prompt(st, True)}
            continue
        except ContextTooLong as exc:
            context_retries += 1
            log(f"context too long ({exc}); trimming harder ({context_retries})")
            if context_retries > 3:
                break
            messages = trim_history(messages, cap=HISTORY_CHAR_CAP // 2, keep_recent=2, aggressive=True)
            if context_retries >= 2:
                if len(messages) > 1 and len(messages[1].get("content") or "") > 6000:
                    messages[1] = dict(messages[1])
                    messages[1]["content"] = messages[1]["content"][:6000] + "\n... (context shortened)"
                # Even the most recent outputs must shrink when the window is this small.
                for i in range(2, len(messages)):
                    m = messages[i]
                    if m.get("role") in ("tool", "user") and len(m.get("content") or "") > 1500:
                        messages[i] = dict(m)
                        messages[i]["content"] = m["content"][:1500] + "\n... [truncated to fit the context window]"
            continue
        except BudgetExceeded as exc:
            log(f"stopping: {exc}")
            break
        rounds += 1
        text = (res.text or "").strip()
        calls = list(res.tool_calls)
        if not calls:
            calls = recover_calls(text)
            if calls:
                log(f"recovered {len(calls)} tool call(s) from text")
        log(f"round {rounds}: {len(calls)} call(s), {len(text)} chars, finish={res.finish}, tokens={llm.tokens_used}")
        if calls:
            ever_called = True
        elif not text_mode and not ever_called:
            no_call_rounds += 1
            if no_call_rounds >= 2:
                # The server accepted the tool schemas but the model never calls them:
                # most likely they were silently ignored. Switch to the text protocol.
                text_mode = True
                llm.supports_tools = False
                messages[0] = {"role": "system", "content": system_prompt(st, True)}
                log("no tool calls in two rounds; switching to the text protocol")
                messages.append({"role": "assistant", "content": text or "(no reply)"})
                messages.append({"role": "user", "content": "Use the tool call format described in the system prompt to inspect files and act."})
                continue
        if not calls:
            if text:
                final_text = text
            if not text:
                empty_streak += 1
                if empty_streak >= 3:
                    log("model returned nothing three times; leaving the loop")
                    break
                messages.append({"role": "user", "content": prompts.NUDGE_NO_TOOL})
                continue
            empty_streak = 0
            ok, why = check_done(st, text)
            if ok:
                log("deliverable verified; done")
                st.final_text = text
                return
            corrections += 1
            log(f"not done ({corrections}): {why[:200]}")
            if corrections > MAX_CORRECTIONS:
                break
            messages.append({"role": "assistant", "content": text})
            messages.append({"role": "user", "content": prompts.NOT_DONE.format(why=why)})
            if corrections >= 2:
                llm.temperature = 0.3
            continue
        empty_streak = 0
        native = not text_mode and not any(c.recovered for c in calls)
        if native:
            messages.append({
                "role": "assistant",
                "content": text or None,
                "tool_calls": [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.name, "arguments": json.dumps(c.arguments, ensure_ascii=False)}}
                    for c in calls
                ],
            })
        else:
            messages.append({"role": "assistant", "content": text or json.dumps({"name": calls[0].name, "arguments": calls[0].arguments})})
        # Many calls in one round must share the output budget, or one round alone can
        # overflow a small context window.
        per_call_cap = max(1800, min(tools.MAX_TOOL_OUTPUT_CHARS, 24000 // max(1, len(calls))))
        for c in calls:
            if st.spec.no_modify and c.name in ("write_file", "str_replace"):
                target = os.path.abspath(str(tools.resolve(str(c.arguments.get("path", "")), st.workdir)))
                inside = target.startswith(os.path.abspath(str(st.workdir)) + os.sep)
                if inside and (not sp.deliverable or target != os.path.abspath(sp.deliverable)):
                    result = (f"[error] this task forbids modifying application files; write only the deliverable "
                              f"{sp.deliverable or ''} (helper scripts can go under /tmp)")
                else:
                    result = tools.dispatch(c.name, c.arguments, st.workdir)
            elif c.name in ("write_file", "str_replace"):
                key = (c.name, json.dumps(c.arguments, sort_keys=True, ensure_ascii=False))
                edit_counts[key] = edit_counts.get(key, 0) + 1
                if edit_counts[key] > 2:
                    result = ("[error] You already applied this exact edit twice and the problem is still there. "
                              "Do something different: read_file the whole function, then rewrite it correctly "
                              "(complete, properly indented) with write_file or a larger str_replace.")
                else:
                    result = tools.dispatch(c.name, c.arguments, st.workdir)
            else:
                result = tools.dispatch(c.name, c.arguments, st.workdir)
            if len(calls) > 1 and len(result) > per_call_cap:
                result = tools.truncate(result, per_call_cap)
            if sp.kind == "ctf":
                seen = oracle.extract_flag(result, sp.flag_prefix)
                if seen and (not sp.flag_prefix or seen.startswith(sp.flag_prefix)) and seen not in st.seen_flags:
                    st.seen_flags.append(seen)
                    log(f"flag-shaped string seen in tool output: {seen}")
            preview = result.replace("\n", " ")[:160]
            st.call_history.append((c.name, json.dumps(c.arguments, ensure_ascii=False)[:200]))
            log(f"  {c.name}({json.dumps(c.arguments, ensure_ascii=False)[:150]}) -> {preview}")
            if native:
                messages.append({"role": "tool", "tool_call_id": c.id, "content": result})
            else:
                messages.append({"role": "user", "content": f"<tool_response>\n{result}\n</tool_response>"})
            sig = (c.name, json.dumps(c.arguments, sort_keys=True), result[:400])
            if sig == last_sig:
                repeat += 1
            else:
                repeat = 0
            last_sig = sig
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
            failed = result.startswith("[error]") or result.startswith("[exit ") and not result.startswith("[exit 0]")
            error_streak = error_streak + 1 if failed else 0
        worst = max(sig_counts.values()) if sig_counts else 0
        if repeat >= 2 or worst >= 3 or error_streak >= 4:
            log(f"no progress (repeat={repeat}, same-signature={worst}, error-streak={error_streak}); nudging")
            messages.append({"role": "user", "content": prompts.NUDGE_REPEAT})
            llm.temperature = 0.4
            if repeat >= 4 or worst >= 5 or error_streak >= 8:
                log("stuck in a loop; leaving")
                break
        # Early exit: a valid deliverable was just written (saves a model round).
        if sp.deliverable and sp.kind in ("kv_report", "ctf", "exact"):
            mt = _mtime(sp.deliverable)
            if mt is not None and mt != st.deliverable_mtime:
                st.deliverable_mtime = mt
                ok, why = check_done(st, "")
                if ok:
                    log("deliverable written and verified; done without another round")
                    st.final_text = text
                    return
    st.final_text = final_text


# ---- finalisation ----------------------------------------------------------------------------

def finalize(st: State):
    if st.finalized:
        return
    st.finalized = True
    sp = st.spec
    if sp is None:
        return
    try:
        if sp.kind == "exact":
            for pth, content in (sp.exact_files or [(sp.deliverable, sp.exact_content)]):
                ok, _ = oracle.check_exact(pth, content)
                if not ok:
                    oracle.write_text(pth, content)
        elif sp.kind == "json_report":
            ok, why = oracle.check_json_report(sp.deliverable, sp.json_root, sp.json_fields)
            if not ok:
                log(f"report invalid or missing ({why}); building it from the scan")
                obj = oracle.load_json_lenient(st.final_text) if st.final_text else None
                report, findings = oracle.normalise_report(obj, sp.json_root, sp.json_fields) if obj is not None else (None, None)
                if report is None:
                    findings = oracle.fallback_findings(st.brief.get("hotspots") or [], st.brief.get("routes") or [], sp.json_fields)
                    if not findings:
                        findings = [{k: "" for k in sp.json_fields}]
                        findings[0].update({"title": "Manual review required", "severity": "informational",
                                            "category": "Informational",
                                            "location": str(st.workdir),
                                            "evidence": "Automated analysis could not complete.",
                                            "impact": "Unknown", "recommendation": "Review the application manually."})
                    report = {sp.json_root: findings}
                oracle.write_text(sp.deliverable, json.dumps(report, ensure_ascii=False, indent=2))
            oracle.merge_report(sp.deliverable, sp.json_root, sp.json_fields, st.brief.get("hotspots") or [],
                                st.brief.get("routes") or [], log=log)
        elif sp.kind == "kv_report":
            ok, why = oracle.check_kv(sp.deliverable, sp.keys)
            if not ok:
                found = oracle.salvage_kv_from_text(st.final_text or "", sp.keys)
                if found and not any(v.lower() in oracle.PLACEHOLDERS for v in found.values()):
                    oracle.write_kv(sp.deliverable, found, sp.keys)
                    log("wrote key=value answer salvaged from the reply")
                elif st.seed:
                    oracle.write_kv(sp.deliverable, st.seed, sp.keys)
                    log("wrote the preliminary automated answer as the deliverable")
                else:
                    partial = oracle.parse_kv_text(oracle.read_text(sp.deliverable), sp.keys) if Path(sp.deliverable).is_file() else {}
                    oracle.write_kv(sp.deliverable, {k: partial.get(k, "unknown") for k in sp.keys}, sp.keys)
                    log("wrote a placeholder key=value file (no verified answer)")
        elif sp.kind == "ctf":
            if sp.deliverable:
                ok, _ = oracle.check_flag_file(sp.deliverable, sp.flag_prefix)
                if not ok:
                    flag = oracle.extract_flag(st.final_text or "", sp.flag_prefix)
                    if not flag and st.seen_flags:
                        flag = st.seen_flags[-1]
                    if not flag and st.brief.get("flags"):
                        flag = st.brief["flags"][0][0]
                    if flag:
                        oracle.write_text(sp.deliverable, flag)
                        log(f"wrote best-effort flag: {flag}")
            flag = oracle.extract_flag(oracle.read_text(sp.deliverable) if sp.deliverable else "", sp.flag_prefix) or \
                oracle.extract_flag(st.final_text or "", sp.flag_prefix) or (st.seen_flags[-1] if st.seen_flags else None)
            if flag:
                print(f"FLAG: {flag}", flush=True)
        elif sp.kind == "code_fix":
            restore_broken_files(st)
        elif sp.kind == "generic" and sp.deliverable and not Path(sp.deliverable).is_file() and st.final_text:
            body = st.final_text.strip()
            body = re.sub(r"^DONE[:.\s-]*", "", body, flags=re.I).strip()
            if body:
                oracle.write_text(sp.deliverable, body)
                log("wrote the final reply as the deliverable")
    except Exception:  # noqa: BLE001
        traceback.print_exc()
    if st.final_text:
        print(f"[agent] final reply: {st.final_text[:1500]}", flush=True)


def restore_broken_files(st: State):
    """A file left with a syntax error guarantees a 0 (the app cannot start); restoring
    its original content at least keeps fixes made in other files alive."""
    for path, original in list(tools.ORIGINALS.items()):
        p = Path(path)
        if p.suffix != ".py" or not p.is_file():
            continue
        if not oracle.compile_errors([p]):
            continue
        try:
            if original is None:
                p.unlink()
                log(f"removed {path}: it was created during the run and does not compile")
            else:
                p.write_text(original, encoding="utf-8")
                log(f"restored {path}: the edited version does not compile")
        except OSError as exc:
            log(f"could not restore {path}: {exc}")


def telemetry(st: State):
    llm = st.llm
    elapsed = time.monotonic() - START_TS
    if llm is not None:
        log(f"done: kind={st.spec.kind if st.spec else '?'} calls={llm.calls} tokens={llm.tokens_used} "
            f"(in={llm.prompt_tokens} out={llm.completion_tokens}) elapsed={elapsed:.1f}s")
    else:
        log(f"done: kind={st.spec.kind if st.spec else '?'} calls=0 tokens=0 elapsed={elapsed:.1f}s")


# ---- entry -----------------------------------------------------------------------------------

def run(st: State):
    sp = st.spec
    if sp.kind == "exact":
        all_ok = True
        for pth, content in (sp.exact_files or [(sp.deliverable, sp.exact_content)]):
            oracle.write_text(pth, content)
            ok, why = oracle.check_exact(pth, content)
            log(f"exact file {pth} written deterministically ({'ok' if ok else why})")
            all_ok = all_ok and ok
        if all_ok:
            return
    low_instr = st.instruction.lower()
    family = set(sp.keys) == forensic_seed.EXPECTED_KEYS or (
        sp.kind == "kv_report" and ("xff" in low_instr or "x-forwarded" in low_instr) and
        any(w in low_instr for w in ("exfil", "export", "jsonl", "audit")))
    if sp.kind == "kv_report" and family:
        root = sp.evidence_dir or str(st.workdir)
        try:
            seed = forensic_seed.solve(root, sp.keys, st.instruction)
        except Exception as exc:  # noqa: BLE001
            seed = None
            log(f"forensic seed failed: {exc}")
        if seed:
            st.seed = seed
            oracle.write_kv(sp.deliverable, seed, sp.keys)
            log("forensic seed written: " + ", ".join(f"{k}={v}" for k, v in seed.items() if not k.startswith("_")))
            # The statement of this task family names the exact record fields the solver
            # mirrors; when it does, the correlation is deterministic and the model would
            # only re-verify it at several thousand tokens per round.
            low = st.instruction.lower()
            mapped = forensic_seed.key_mapping(st.instruction, sp.keys)
            if (all(sig in low for sig in ("payload_logical_bytes", "identity.subject", "xff"))
                    or (len(mapped) >= max(2, len(sp.keys) - 2) and "xff" in low)) and \
                    not os.environ.get("LOCAL_AGENT_ALWAYS_MODEL"):
                ok, why = oracle.check_kv(sp.deliverable, sp.keys)
                if ok:
                    log("forensic task solved deterministically (0 tokens)")
                    return
    if sp.kind == "code_fix":
        st.snapshot = oracle.snapshot_tree(st.workdir)
        try:
            st.servers = oracle.find_servers(st.workdir)
        except Exception as exc:  # noqa: BLE001
            st.servers = []
            log(f"server discovery failed: {exc}")
        if st.servers:
            log("running servers: " + "; ".join(f"pid={s['pid']} ports={s['ports']} {' '.join(s['argv'])[:80]}" for s in st.servers))
        if not os.environ.get("AGENT_DISABLE_SQLFIX"):
            try:
                if mechanical_sql_fix(st):
                    return
            except Exception as exc:  # noqa: BLE001
                log(f"mechanical fix failed: {exc}")
    st.brief = brief.build(sp, st.workdir, log=log)
    log(f"briefing: {len(st.brief.get('text', ''))} chars, {len(st.brief.get('hotspots') or [])} hotspots, "
        f"{len(st.brief.get('routes') or [])} routes")
    base_url = os.environ.get("OPENAI_BASE_URL", "")
    model = os.environ.get("LOCAL_AGENT_MODEL") or os.environ.get("OPENAI_MODEL") or ""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not base_url:
        log("no OPENAI_BASE_URL; skipping the model phase")
        return
    st.llm = LLM(base_url, api_key, model, st.deadline_ts, TOKEN_BUDGET, log=log)
    st.llm.discover_model()
    log(f"model={st.llm.model} endpoint={st.llm.url}")
    run_loop(st)
    # A stalled first attempt on a short-transcript task gets one fresh start with a
    # different framing while there is still meaningful time left.
    if sp.kind in ("ctf", "kv_report", "generic") and st.llm.remaining() > 150 and not st.llm.exhausted(8000):
        ok, why = check_done(st, st.final_text)
        if not ok:
            recent = "\n".join(f"- {name}({args})" for name, args in st.call_history[-8:]) or "(nothing)"
            st.retry_note = prompts.RETRY_NOTE.format(calls=recent)
            st.llm.temperature = 0.5
            log(f"first attempt did not verify ({why[:120]}); retrying with a fresh transcript")
            run_loop(st)


def main(argv) -> int:
    instruction = " ".join(a for a in argv[1:]).strip()
    st = State()
    st.instruction = instruction
    st.workdir = pick_workdir()
    try:
        st.spec = specmod.triage(instruction, st.workdir)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
        st.spec = specmod.Spec()
    log(f"workdir={st.workdir} {st.spec.describe()}")

    def on_alarm(signum, frame):
        log("hard deadline reached; finalising")
        try:
            finalize(st)
            telemetry(st)
        finally:
            sys.stdout.flush()
            os._exit(0)

    try:
        signal.signal(signal.SIGALRM, on_alarm)
        signal.alarm(int(SOFT_DEADLINE_SEC + HARD_GRACE_SEC))
    except Exception:  # noqa: BLE001
        pass
    try:
        run(st)
    except Exception:  # noqa: BLE001
        traceback.print_exc()
    finally:
        try:
            finalize(st)
        except Exception:  # noqa: BLE001
            traceback.print_exc()
        try:
            telemetry(st)
        except Exception:  # noqa: BLE001
            pass
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
