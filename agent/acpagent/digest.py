"""Pre-computed facts about evidence files, for the forensics briefing.

A small model cannot hold a 25k-line log in context, and it counts badly. Giving it
the shape of every file up front — timestamp range, most frequent addresses and
accounts, event types and their counts, JSON field names — turns "find the needle"
into "confirm the needle", which is a task it can do.
"""

import json
import os
import re
from collections import Counter
from pathlib import Path

MAX_FILES = 30
MAX_BYTES = 30_000_000
MAX_LINES = 200_000
PER_FILE_CHARS = 1300
TOTAL_CHARS = 7000

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?"
    r"|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}\d{1,2} \d{2}:\d{2}:\d{2}"
)
_USER = re.compile(
    r"(?:for (?:invalid user )?|\buser[=: ]+|\busername[=:]\s*\"?|\bsubject\"?\s*[:=]\s*\"?|\baccount[=:]\s*\"?|\blogin[=:]\s*\"?|\bacct[=:]\s*\"?)"
    r"([A-Za-z][A-Za-z0-9_.@-]{1,40})"
)
_EVENT_WORDS = re.compile(
    r"\b(Accepted (?:password|publickey)|Failed password|authentication failure|session opened|session closed|"
    r"Invalid user|POSSIBLE BREAK-IN|sudo|COMMAND=|Connection closed|Disconnected|"
    r"[A-Z][A-Z_]{3,}(?:_[A-Z]+)*)\b"
)
_KV_EVENT = re.compile(r"\b(?:event|action|type|decision|result|status|verdict|method)\"?\s*[=:]\s*\"?([A-Za-z_][A-Za-z0-9_./-]{1,40})")
_HTTP_REQ = re.compile(r"\"(GET|POST|PUT|DELETE|PATCH|HEAD) ([^\s\"]+)")


def _top(counter: Counter, n: int) -> str:
    return ", ".join(f"{k} ({c})" for k, c in counter.most_common(n))


def _flatten(obj, prefix="", out=None, depth=0):
    if out is None:
        out = {}
    if isinstance(obj, dict) and depth < 5:
        for k, v in obj.items():
            _flatten(v, f"{prefix}{k}.", out, depth + 1)
    else:
        out[prefix[:-1]] = obj
    return out


def digest_file(p: Path) -> str:
    try:
        size = p.stat().st_size
        if size > MAX_BYTES:
            return f"(skipped: {size} bytes)"
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    n = len(lines)
    sample = lines[:MAX_LINES]
    out = [f"{n} lines, {size} bytes"]
    comments = [ln for ln in sample[:5] if ln.startswith("#")]
    if comments:
        out.append("header notes: " + " | ".join(c[:160] for c in comments[:3]))
    # JSONL?
    json_rows = 0
    fields = {}
    ev = Counter()
    subj = Counter()
    if p.suffix.lower() in (".jsonl", ".ndjson") or (sample and sample[0].lstrip().startswith("{")):
        for ln in sample:
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                row = json.loads(ln)
            except ValueError:
                continue
            json_rows += 1
            flat = _flatten(row)
            for k, v in flat.items():
                if k not in fields:
                    fields[k] = v
                lk = k.lower()
                if lk.endswith(("event", "action", "type", "result", "status", "decision", "method", "outcome")) and isinstance(v, str):
                    ev[f"{k}={v}"] += 1
                if lk.endswith(("subject", "user", "username", "account", "principal", "actor", "login", "uid")) and isinstance(v, str):
                    subj[f"{k}={v}"] += 1
        if json_rows:
            out.append(f"JSONL: {json_rows} records; fields: " + ", ".join(f"{k}={json.dumps(v)[:30]}" for k, v in list(fields.items())[:18]))
            if ev:
                out.append("value counts: " + _top(ev, 12))
            if subj:
                out.append("identities: " + _top(subj, 10))
    if not json_rows:
        ips = Counter(_IPV4.findall(text[:5_000_000]))
        if ips:
            out.append("top IPs: " + _top(ips, 8))
        users = Counter(m.group(1) for m in _USER.finditer(text[:5_000_000]))
        if users:
            out.append("top accounts: " + _top(users, 8))
        events = Counter(m.group(1) for m in _EVENT_WORDS.finditer(text[:5_000_000]))
        events = Counter({k: v for k, v in events.items() if not k.isupper() or len(k) > 4})
        if events:
            out.append("event markers: " + _top(events, 10))
        kv = Counter(f"{m.group(0).split('=')[0].split(':')[0].strip().strip(chr(34))}={m.group(1)}" for m in _KV_EVENT.finditer(text[:5_000_000]))
        if kv:
            out.append("key=value markers: " + _top(kv, 10))
        reqs = Counter(f"{m.group(1)} {m.group(2)}" for m in _HTTP_REQ.finditer(text[:5_000_000]))
        if reqs:
            out.append("HTTP requests: " + _top(reqs, 8))
    ts = _TS.findall(text[:5_000_000])
    if ts:
        out.append(f"timestamps: {len(ts)} found, first={ts[0]}, last={ts[-1]}, min={min(ts)}, max={max(ts)}")
    cont = sum(1 for ln in sample if ln[:1] in ("\t", " ") and ln.strip())
    if cont:
        out.append(f"NOTE: {cont} continuation lines start with whitespace (multi-line records — join them to the previous line)")
    return "\n".join(out)


def digest_dir(root: Path) -> str:
    root = Path(root)
    parts = []
    total = 0
    files = sorted(p for p in root.rglob("*") if p.is_file() and not p.name.startswith("."))[:MAX_FILES]
    for p in files:
        try:
            with p.open("rb") as fh:
                head = fh.read(2048)
        except OSError:
            continue
        if b"\x00" in head:
            continue
        d = digest_file(p)
        if not d:
            continue
        block = f"## {os.path.relpath(p, root)}\n{d[:PER_FILE_CHARS]}"
        parts.append(block)
        total += len(block)
        if total > TOTAL_CHARS:
            break
    return "\n".join(parts)
