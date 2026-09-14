"""Deterministic per-entity profiles of evidence files, with timestamps in UTC.

A small model counts badly, mixes up "before" and "after", and forgets time zones.
These tables answer the questions a forensics statement usually asks — who failed how
often from where, when the first success happened, what the rare events were — so the
model only has to pick the row the statement describes and copy the values.
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except Exception:  # noqa: BLE001
    ZoneInfo = None

MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_TZ_NAME_RE = re.compile(r"(?:host_|server_|log_|local_)?(?:tz|timezone|time zone)\s*[=:]?\s*([A-Z][A-Za-z]+/[A-Za-z_+-]+(?:/[A-Za-z_+-]+)?|UTC|GMT)\b")
_TZ_OFFSET_RE = re.compile(r"(?:UTC|GMT)\s*([+-]\d{1,2})(?::?(\d{2}))?\b|explicit\s+([+-]\d{2}):(\d{2})|(?<![\w:])([+-]\d{2}):(\d{2})\s*\(")
_YEAR_RE = re.compile(r"\byear\s*[:=]?\s*(20\d{2})\b|\b(20\d{2})\b")
_SYSLOG_RE = re.compile(
    r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
_ISO_RE = re.compile(r"(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
_CLF_TS_RE = re.compile(r"\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}:\d{2}:\d{2})(?: ([+-]\d{4}))?\]")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_SSH_EVENT_RE = re.compile(
    r"(?P<kind>Accepted (?:password|publickey|keyboard-interactive/pam)|Failed (?:password|publickey|keyboard-interactive/pam)|Invalid user|"
    r"authentication failure|session opened|session closed|Connection closed|Disconnected|POSSIBLE BREAK-IN)"
)
_SSH_USER_RE = re.compile(r"\bfor (?:invalid user )?(?P<user>[A-Za-z0-9_.@-]+) from (?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
_SSH_USER2_RE = re.compile(r"\buser[= ](?P<user>[A-Za-z0-9_.@-]+)|\brhost=(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
_CLF_RE = re.compile(r'^(?P<ip>\S+) \S+ (?P<auth>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\d+|-)')
_XFF_RE = re.compile(r'xff="([^"]*)"|X-Forwarded-For:\s*([^\s"]+(?:,\s*[^\s"]+)*)', re.I)
_SUSPICIOUS = re.compile(r"\.\./|%2e%2e|union\s+select|'\s*or\s*'|%27|<script|/etc/passwd|cmd=|;\s*(?:id|ls|cat|whoami)\b|\$\(|`|sleep\(|benchmark\(|/wp-admin|/\.git|/\.env|passwd|shadow", re.I)
# attack payloads outrank generic scanner noise when picking what to show
_SEVERE = re.compile(r"\.\./|%2e%2e|union\s+select|'\s*or\s*'|<script|/etc/passwd|cmd=|;\s*(?:id|ls|cat|whoami)\b|\$\(|`|sleep\(|/\.env|shadow", re.I)
_PRIVATE = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "127.")


def _is_private(ip: str) -> bool:
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    m = re.match(r"172\.(\d+)\.", ip)
    return bool(m and 16 <= int(m.group(1)) <= 31)


# ---- time zones --------------------------------------------------------------------------

def detect_tz(header_text: str):
    """(tzinfo or None, label, year or None) from the comment lines of a file."""
    label, tz, year = "", None, None
    m = _TZ_NAME_RE.search(header_text)
    if m:
        name = m.group(1)
        if name in ("UTC", "GMT"):
            tz, label = timezone.utc, "UTC"
        elif ZoneInfo is not None:
            try:
                tz, label = ZoneInfo(name), name
            except Exception:  # noqa: BLE001
                tz = None
    if tz is None:
        m2 = _TZ_OFFSET_RE.search(header_text)
        if m2:
            if m2.group(1):
                hours, mins = int(m2.group(1)), int(m2.group(2) or 0)
            elif m2.group(3):
                hours, mins = int(m2.group(3)), int(m2.group(4))
            else:
                hours, mins = int(m2.group(5)), int(m2.group(6))
            sign = -1 if hours < 0 else 1
            tz = timezone(timedelta(hours=hours, minutes=sign * mins))
            label = f"UTC{hours:+03d}:{mins:02d}"
    ym = _YEAR_RE.search(header_text)
    if ym:
        year = int(ym.group(1) or ym.group(2))
    return tz, label, year


def fmt_utc(dt: datetime, keep_fraction: bool = True, digits=None) -> str:
    """ISO-8601 UTC. `digits` reproduces the source's fractional-second width so a
    value can be copied verbatim (".900" stays ".900")."""
    dt = dt.astimezone(timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if digits:
        base += "." + f"{dt.microsecond:06d}"[:digits]
    elif keep_fraction and dt.microsecond:
        base += "." + f"{dt.microsecond:06d}".rstrip("0")
    return base + "Z"


def _fraction_digits(text: str) -> int:
    m = _ISO_RE.search(text)
    if m and m.group(3):
        return len(m.group(3)) - 1
    return 0


def parse_ts(text: str, tz=None, year=None):
    """Parse the first timestamp in `text` into an aware datetime (None if unknown)."""
    m = _ISO_RE.search(text)
    if m:
        date, clock, frac, off = m.groups()
        try:
            dt = datetime.fromisoformat(f"{date}T{clock}{frac or ''}")
        except ValueError:
            return None
        if off:
            if off == "Z":
                return dt.replace(tzinfo=timezone.utc)
            sign = 1 if off[0] == "+" else -1
            hh, mm = int(off[1:3]), int(off[-2:])
            return dt.replace(tzinfo=timezone(sign * timedelta(hours=hh, minutes=mm)))
        return dt.replace(tzinfo=tz) if tz is not None else None
    m = _CLF_TS_RE.search(text)
    if m:
        day, mon, yr, clock, off = m.groups()
        try:
            dt = datetime(int(yr), MONTHS.get(mon, 1), int(day), *map(int, clock.split(":")))
        except ValueError:
            return None
        if off:
            sign = 1 if off[0] == "+" else -1
            return dt.replace(tzinfo=timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))))
        return dt.replace(tzinfo=tz) if tz is not None else None
    m = _SYSLOG_RE.match(text)
    if m and tz is not None and year:
        try:
            dt = datetime(year, MONTHS[m.group("mon")], int(m.group("day")), *map(int, m.group("time").split(":")))
        except ValueError:
            return None
        return dt.replace(tzinfo=tz)
    return None


def utc_note(text: str, tz, label, year) -> str:
    dt = parse_ts(text, tz, year)
    if dt is None:
        return ""
    digits = _fraction_digits(text)
    return f"  → UTC {fmt_utc(dt, digits=digits)}" + (f" (from {label})" if label and label != "UTC" else "")


# ---- SSH / auth logs -----------------------------------------------------------------------

def auth_facts(lines, tz, label, year):
    """Structured per-IP facts of an sshd/auth log (the text profile and the answer seed
    are both built from this)."""
    per_ip = {}
    accepted_lines = []
    order = 0
    for ln in lines:
        m = _SSH_EVENT_RE.search(ln)
        if not m:
            continue
        kind = m.group("kind")
        um = _SSH_USER_RE.search(ln)
        user = um.group("user") if um else None
        ip = um.group("ip") if um else None
        if ip is None:
            ipm = _IPV4.search(ln)
            ip = ipm.group(0) if ipm else None
        if user is None:
            um2 = _SSH_USER2_RE.search(ln)
            user = um2.group("user") if um2 and um2.group("user") else None
        if ip is None:
            continue
        order += 1
        rec = per_ip.setdefault(ip, {"failed": 0, "accepted_pw": 0, "accepted_key": 0, "first_accept": None,
                                     "failed_before": 0, "users": Counter(), "invalid": 0, "lines": [],
                                     "first_failed": None, "first": None, "last": None})
        rec["lines"].append(ln)
        rec["first"] = rec["first"] or ln
        rec["last"] = ln
        if kind.startswith("Failed"):
            rec["failed"] += 1
            rec["first_failed"] = rec["first_failed"] or ln
            if rec["first_accept"] is None:
                rec["failed_before"] += 1
            if user:
                rec["users"][user] += 1
        elif kind.startswith("Accepted"):
            if "publickey" in kind:
                rec["accepted_key"] += 1
            else:
                rec["accepted_pw"] += 1
            if rec["first_accept"] is None:
                rec["first_accept"] = (ln, user, kind, order)
            if "publickey" not in kind and rec.get("first_accept_pw") is None:
                rec["first_accept_pw"] = (ln, user, kind, order)
            accepted_lines.append(ln)
        elif kind == "Invalid user":
            rec["invalid"] += 1
    for rec in per_ip.values():
        rec.setdefault("first_accept_pw", None)
    return {"per_ip": per_ip, "accepted": accepted_lines, "tz": tz, "label": label, "year": year}


def auth_profile(lines, tz, label, year, max_rows: int = 8):
    facts = auth_facts(lines, tz, label, year)
    per_ip, accepted_lines = facts["per_ip"], facts["accepted"]
    if not per_ip:
        return ""
    rows = sorted(per_ip.items(), key=lambda kv: (-(kv[1]["failed"] + kv[1]["invalid"]), -kv[1]["accepted_pw"], kv[0]))
    out = ["SSH/auth profile per source IP (failed logins / accepted logins; 'failed before first success' counts this IP's "
           "Failed lines that precede its first Accepted line):"]
    for ip, r in rows[:max_rows]:
        acc = []
        if r["accepted_pw"]:
            acc.append(f"{r['accepted_pw']} accepted(password)")
        if r["accepted_key"]:
            acc.append(f"{r['accepted_key']} accepted(publickey)")
        first = ""
        if r["first_accept"]:
            ln, user, kind, _ = r["first_accept"]
            first = f"; first success: {kind} as {user} on `{ln.split(' sshd')[0].strip() if ' sshd' in ln else ln[:24]}`{utc_note(ln, tz, label, year)}; failed before it: {r['failed_before']}"
        users = ", ".join(f"{u}({c})" for u, c in r["users"].most_common(4))
        out.append(f"- {ip}: {r['failed']} failed" + (f" ({r['invalid']} invalid-user)" if r["invalid"] else "") +
                   (", " + ", ".join(acc) if acc else ", no successful login") + first +
                   (f"; users tried: {users}" if users else ""))
    if accepted_lines:
        out.append("Accepted (successful login) lines, in file order:")
        for ln in accepted_lines[:12]:
            out.append(f"  {ln[:170]}{utc_note(ln, tz, label, year)}")
        if len(accepted_lines) > 12:
            out.append(f"  ... {len(accepted_lines) - 12} more accepted lines")
    return "\n".join(out)


# ---- web / proxy access logs ---------------------------------------------------------------

def access_facts(lines, tz, label, year):
    """Structured per-client facts of a CLF/nginx/apache/proxy access log."""
    per_ip = {}
    xff_clients = Counter()
    suspicious_lines = []
    for ln in lines:
        m = _CLF_RE.match(ln)
        if not m:
            continue
        ip = m.group("ip")
        rec = per_ip.setdefault(ip, {"n": 0, "err": 0, "sus": 0, "first": None, "last": None, "paths": Counter(), "bytes": 0,
                                     "users": Counter(), "first_sus": None, "first_sus_ok": None, "severe": 0, "lines": [],
                                     "parsed": []})
        rec["n"] += 1
        rec["lines"].append(ln)
        rec["parsed"].append({"method": m.group("method"), "path": m.group("path"), "status": m.group("status"),
                              "size": m.group("size"), "line": ln})
        if m.group("status")[0] in ("4", "5"):
            rec["err"] += 1
        if _SUSPICIOUS.search(m.group("path")) or _SUSPICIOUS.search(ln):
            rec["sus"] += 1
            severe = bool(_SEVERE.search(m.group("path")) or _SEVERE.search(ln))
            if severe:
                rec["severe"] += 1
            suspicious_lines.append((0 if severe else 1, ln))
            if rec["first_sus"] is None:
                rec["first_sus"] = ln
            if rec["first_sus_ok"] is None and m.group("status").startswith("2"):
                rec["first_sus_ok"] = ln
        rec["paths"][f"{m.group('method')} {m.group('path')[:60]}"] += 1
        if m.group("size") != "-":
            rec["bytes"] += int(m.group("size"))
        if m.group("auth") != "-":
            rec["users"][m.group("auth")] += 1
        rec["first"] = rec["first"] or ln
        rec["last"] = ln
        xm = _XFF_RE.search(ln)
        if xm:
            chain = [h.strip() for h in (xm.group(1) or xm.group(2) or "").split(",") if h.strip()]
            public = [h for h in chain if _IPV4.fullmatch(h) and not _is_private(h)]
            if public:
                xff_clients[public[-1]] += 1
    return {"per_ip": per_ip, "xff": xff_clients, "suspicious": suspicious_lines, "tz": tz, "label": label, "year": year}


def access_profile(lines, tz, label, year, max_rows: int = 8):
    facts = access_facts(lines, tz, label, year)
    per_ip, xff_clients, suspicious_lines = facts["per_ip"], facts["xff"], facts["suspicious"]
    if not per_ip:
        return ""
    rows = sorted(per_ip.items(), key=lambda kv: (-kv[1]["severe"], -kv[1]["sus"], -kv[1]["n"]))
    out = ["HTTP access profile per client IP (requests / 4xx-5xx / suspicious payloads [attack payloads such as ../, "
           "SQL, command injection count as 'severe'] / bytes served):"]
    for ip, r in rows[:max_rows]:
        top = ", ".join(f"{p}({c})" for p, c in r["paths"].most_common(3))
        users = ", ".join(f"{u}({c})" for u, c in r["users"].most_common(3))
        line = (f"- {ip}: {r['n']} req, {r['err']} errors, {r['sus']} suspicious ({r['severe']} severe), {r['bytes']} bytes; "
                f"first request `{_ts_of(r['first'])}`{utc_note(r['first'], tz, label, year)}; last `{_ts_of(r['last'])}`"
                + (f"; auth users: {users}" if users else "") + f"; top: {top}")
        if r["first_sus"]:
            line += f"\n    first suspicious request: {r['first_sus'][:190]}{utc_note(r['first_sus'], tz, label, year)}"
        if r["first_sus_ok"]:
            line += f"\n    first suspicious request answered 2xx: {r['first_sus_ok'][:190]}{utc_note(r['first_sus_ok'], tz, label, year)}"
        out.append(line)
    if xff_clients:
        out.append("X-Forwarded-For public client IPs (last non-private hop): " + ", ".join(f"{k} ({c})" for k, c in xff_clients.most_common(8)))
    if suspicious_lines:
        suspicious_lines.sort(key=lambda t: t[0])
        out.append("Suspicious request lines (attack payloads first, in file order):")
        for _, ln in suspicious_lines[:10]:
            out.append(f"  {ln[:200]}")
    return "\n".join(out)


def _ts_of(ln: str) -> str:
    m = _CLF_TS_RE.search(ln) or _ISO_RE.search(ln) or _SYSLOG_RE.match(ln)
    return m.group(0)[:40] if m else ln[:24]


# ---- JSONL audit streams -------------------------------------------------------------------

def jsonl_profile(rows, tz, label, year, max_rows: int = 8):
    if not rows:
        return ""
    per_subject = {}
    events = Counter()
    for row in rows:
        flat = _flatten(row)
        subj = next((v for k, v in flat.items() if k.split(".")[-1] in ("subject", "user", "username", "account", "principal", "actor", "login") and isinstance(v, str)), None)
        ev = next((v for k, v in flat.items() if k.split(".")[-1] in ("event", "action", "type", "operation") and isinstance(v, str)), None)
        size = 0
        for k, v in flat.items():
            if k.split(".")[-1] in ("bytes", "size", "payload_logical_bytes", "length", "volume") and isinstance(v, (int, float)) and not isinstance(v, bool):
                size = max(size, int(v))
        if ev:
            events[ev] += 1
        if subj:
            rec = per_subject.setdefault(subj, {"n": 0, "events": Counter(), "bytes": 0, "max": (0, None)})
            rec["n"] += 1
            if ev:
                rec["events"][ev] += 1
            rec["bytes"] += size
            if size > rec["max"][0]:
                rec["max"] = (size, row)
    out = []
    if events:
        out.append("event counts: " + ", ".join(f"{k} ({c})" for k, c in events.most_common(12)))
    if per_subject:
        out.append("per identity (records / bytes total / largest record):")
        rows_sorted = sorted(per_subject.items(), key=lambda kv: (-kv[1]["bytes"], -kv[1]["n"]))
        for subj, r in rows_sorted[:max_rows]:
            mx = r["max"][1]
            mx_txt = ""
            if mx:
                mx_txt = f"; largest: {r['max'][0]} bytes at ts={mx.get('ts') or mx.get('timestamp') or mx.get('time')}"
            out.append(f"- {subj}: {r['n']} records, {r['bytes']} bytes, events: " + ", ".join(f"{k}({c})" for k, c in r["events"].most_common(4)) + mx_txt)
    # rare events in full
    total = len(rows)
    rare = {k for k, c in events.items() if c <= max(5, total * 0.01)}
    if rare:
        out.append("rare-event records in full (these are usually the ones the task is about):")
        shown = 0
        for row in rows:
            flat = _flatten(row)
            ev = next((v for k, v in flat.items() if k.split(".")[-1] in ("event", "action", "type", "operation") and isinstance(v, str)), None)
            if ev in rare:
                line = json.dumps(row, ensure_ascii=False)
                ts = row.get("ts") or row.get("timestamp") or row.get("time") or ""
                out.append(f"  {line[:260]}" + (utc_note(str(ts), tz, label, year) if ts else ""))
                shown += 1
                if shown >= 12:
                    break
    return "\n".join(out)


def _flatten(obj, prefix="", out=None, depth=0):
    if out is None:
        out = {}
    if isinstance(obj, dict) and depth < 5:
        for k, v in obj.items():
            _flatten(v, f"{prefix}{k}.", out, depth + 1)
    else:
        out[prefix[:-1]] = obj
    return out


# ---- generic rare-line listing --------------------------------------------------------------

_MARKER_RE = re.compile(r"\b(?:decision|event|action|result|status|verdict|type)=([A-Za-z_][A-Za-z0-9_-]{2,40})|\b([A-Z][A-Z_]{4,})\b")


def rare_lines(lines, tz, label, year, max_lines: int = 10):
    markers = Counter()
    per_line = []
    for ln in lines:
        if not ln.strip() or ln.lstrip().startswith("#"):
            per_line.append(None)
            continue
        found = set(m.group(1) or m.group(2) for m in _MARKER_RE.finditer(ln))
        per_line.append(found)
        for f in found:
            markers[f] += 1
    n = sum(1 for x in per_line if x)
    data = [ln for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
    if len(data) <= 6:
        return "all data lines (small file):\n" + "\n".join(f"  {ln[:220]}{utc_note(ln, tz, label, year)}" for ln in data)
    if not markers or n < 3:
        return ""
    rare = {k for k, c in markers.items() if c <= max(2, int(n * 0.05))}
    if not rare:
        return ""
    out = ["rare markers: " + ", ".join(f"{k} ({markers[k]})" for k in sorted(rare, key=lambda k: markers[k])[:8]) + " — their lines in full:"]
    shown = 0
    for ln, found in zip(lines, per_line):
        if found and found & rare:
            out.append(f"  {ln[:200]}{utc_note(ln, tz, label, year)}")
            shown += 1
            if shown >= max_lines:
                break
    return "\n".join(out)


# ---- entry -----------------------------------------------------------------------------------

def load_logical(p: Path):
    """(logical lines with continuations joined, tz, label, year, header) of a text file."""
    try:
        if p.stat().st_size > 40_000_000:
            return None
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    header = "\n".join(ln for ln in lines[:8] if ln.startswith("#"))
    tz, label, year = detect_tz(header)
    if year is None:
        ym = re.search(r"\b(20\d{2})-\d{2}-\d{2}", text[:20000])
        year = int(ym.group(1)) if ym else None
    logical = []
    for ln in lines:
        if ln[:1] in ("\t", " ") and logical:
            logical[-1] += " " + ln.strip()
        else:
            logical.append(ln)
    return logical, tz, label, year, header


def file_kind(logical, p: Path) -> str:
    if any(" sshd" in ln or "Failed password" in ln or "Accepted " in ln for ln in logical[:400]):
        return "auth"
    if any(_CLF_RE.match(ln) for ln in logical[:50]):
        return "access"
    if p.suffix.lower() in (".jsonl", ".ndjson") or (logical and logical[0].lstrip().startswith("{")):
        return "jsonl"
    return "other"


def file_facts(p: Path):
    """Structured facts of one evidence file (None when it is not a recognised log)."""
    loaded = load_logical(p)
    if loaded is None:
        return None
    logical, tz, label, year, header = loaded
    kind = file_kind(logical, p)
    if kind == "auth":
        facts = auth_facts(logical, tz, label, year)
    elif kind == "access":
        facts = access_facts(logical, tz, label, year)
    else:
        return None
    facts.update({"path": p, "kind": kind, "lines": logical})
    return facts


def dir_facts(root: Path, limit_files: int = 30):
    out = []
    for p in sorted(x for x in Path(root).rglob("*") if x.is_file() and not x.name.startswith("."))[:limit_files]:
        try:
            with p.open("rb") as fh:
                if b"\x00" in fh.read(2048):
                    continue
        except OSError:
            continue
        f = file_facts(p)
        if f and f["per_ip"]:
            out.append(f)
    return out


def profile_file(p: Path, max_chars: int = 2600) -> str:
    loaded = load_logical(p)
    if loaded is None:
        return ""
    logical, tz, label, year, header = loaded
    lines = logical
    parts = []
    if tz is not None:
        note = f"time zone of this file: {label}" if label else "time zone: explicit offsets"
        if year and any(_SYSLOG_RE.match(ln) for ln in lines[:50]):
            note += f"; syslog lines have no year — year {year} from the header"
        parts.append(note + ". All '→ UTC' values below were computed from that.")
    kind = file_kind(logical, p)
    if kind == "auth":
        t = auth_profile(logical, tz, label, year)
        if t:
            parts.append(t)
    elif kind == "access":
        t = access_profile(logical, tz, label, year)
        if t:
            parts.append(t)
    elif kind == "jsonl":
        rows = []
        for ln in logical[:200_000]:
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    rows.append(json.loads(ln))
                except ValueError:
                    pass
        t = jsonl_profile(rows, tz, label, year)
        if t:
            parts.append(t)
    else:
        t = rare_lines(logical, tz, label, year)
        if t:
            parts.append(t)
    return "\n".join(parts)[:max_chars]


def profile_dir(root: Path, max_total: int = 9000) -> str:
    root = Path(root)
    out = []
    total = 0
    for p in sorted(x for x in root.rglob("*") if x.is_file() and not x.name.startswith("."))[:30]:
        try:
            with p.open("rb") as fh:
                if b"\x00" in fh.read(2048):
                    continue
        except OSError:
            continue
        t = profile_file(p)
        if not t:
            continue
        block = f"## {p.relative_to(root)}\n{t}"
        out.append(block)
        total += len(block)
        if total > max_total:
            break
    return "\n".join(out)


def utc_candidates(root: Path, limit_files: int = 30):
    """Every timestamp in the evidence converted to UTC (second precision), for checks."""
    cands = set()
    for p in sorted(x for x in Path(root).rglob("*") if x.is_file())[:limit_files]:
        try:
            if p.stat().st_size > 40_000_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        tz, label, year = detect_tz("\n".join(ln for ln in lines[:8] if ln.startswith("#")))
        if year is None:
            ym = re.search(r"\b(20\d{2})-\d{2}-\d{2}", text[:20000])
            year = int(ym.group(1)) if ym else None
        for ln in lines[:300_000]:
            dt = parse_ts(ln, tz, year)
            if dt is not None:
                cands.add(fmt_utc(dt, keep_fraction=False))
                cands.add(fmt_utc(dt, keep_fraction=True))
                d = _fraction_digits(ln)
                if d:
                    cands.add(fmt_utc(dt, digits=d))
    return cands
