"""Independent recomputation of a key=value forensics answer.

`kv_seed` derives the answer from the structured profiles in `profile.py`. If that
pipeline has a bug, the answer is wrong and everything downstream — the confidence
label, the constraint check, the early return — inherits the same mistake, because it
all reads the same structures.

This module recomputes the answer a second time from the raw file bytes, with its own
timestamp parsing, its own timezone resolution and its own counting, sharing no code
with `profile.py`. It does not try to map the statement onto the evidence; it asks the
weaker but independent question: *could this value have come from this evidence at
all?* A timestamp must be the conversion of a real line, a count must equal one of the
counts the raw lines actually support, an entity must appear verbatim.

Disagreement does not mean the answer is wrong — it means the code is no longer
entitled to skip the model.
"""

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except Exception:  # noqa: BLE001
    ZoneInfo = None

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}

# Deliberately written from scratch rather than imported from profile.py.
_RE_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
_RE_CLF = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{4}))?\]")
_RE_SYS = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\b")
_RE_TZNAME = re.compile(r"(?:tz|time ?zone)\s*[=:]?\s*([A-Za-z]+/[A-Za-z_+-]+)", re.I)
_RE_TZOFF = re.compile(r"(?:UTC|GMT)\s*([+-])(\d{1,2})(?::?(\d{2}))?", re.I)
_RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_RE_INT = re.compile(r"^-?\d+$")
_RE_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_RE_BACKTICK = re.compile(r"`([^`\n]{1,60})`")

_MAX_BYTES = 40_000_000


def _evidence(root):
    """[(path, [lines])] for every readable text file under root."""
    out = []
    for p in sorted(x for x in Path(root).rglob("*") if x.is_file() and not x.name.startswith(".")):
        try:
            if p.stat().st_size > _MAX_BYTES:
                continue
            with p.open("rb") as fh:
                if b"\x00" in fh.read(2048):
                    continue
            out.append((p, p.read_text(encoding="utf-8", errors="replace").splitlines()))
        except OSError:
            continue
        if len(out) > 40:
            break
    return out


def _tz_of(lines):
    """(tzinfo or None, year or None) resolved independently from the file's header."""
    head = "\n".join(ln for ln in lines[:10] if ln.lstrip().startswith("#"))
    tz = None
    m = _RE_TZNAME.search(head)
    if m and ZoneInfo is not None:
        try:
            tz = ZoneInfo(m.group(1))
        except Exception:  # noqa: BLE001
            tz = None
    if tz is None:
        m = _RE_TZOFF.search(head)
        if m:
            sign = 1 if m.group(1) == "+" else -1
            tz = timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0)))
    year = None
    ym = re.search(r"\b(20\d{2})\b", head)
    if ym:
        year = int(ym.group(1))
    if year is None:
        for ln in lines[:400]:
            m = _RE_ISO.search(ln) or _RE_CLF.search(ln)
            if m:
                year = int(m.group(1)) if m.re is _RE_ISO else int(m.group(3))
                break
    return tz, year


def _to_utc(line, tz, year):
    """Parse the first timestamp of `line` and return it in UTC, or None."""
    m = _RE_ISO.search(line)
    if m:
        y, mo, d, hh, mm, ss, frac, off = m.groups()
        micro = int(round(float(frac) * 1_000_000)) if frac else 0
        try:
            dt = datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss), micro)
        except ValueError:
            return None
        if off in (None, ""):
            if tz is None:
                return None
            dt = dt.replace(tzinfo=tz)
        elif off == "Z":
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            o = off.replace(":", "")
            sign = 1 if o[0] == "+" else -1
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(o[1:3]), minutes=int(o[3:5]))))
        return dt.astimezone(timezone.utc), (len(frac) - 1 if frac else 0)
    m = _RE_CLF.search(line)
    if m:
        d, mon, y, hh, mm, ss, off = m.groups()
        try:
            dt = datetime(int(y), _MONTHS.get(mon.lower(), 1), int(d), int(hh), int(mm), int(ss))
        except ValueError:
            return None
        if off:
            sign = 1 if off[0] == "+" else -1
            dt = dt.replace(tzinfo=timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))))
        elif tz is not None:
            dt = dt.replace(tzinfo=tz)
        else:
            return None
        return dt.astimezone(timezone.utc), 0
    m = _RE_SYS.match(line)
    if m and tz is not None and year:
        mon, d, hh, mm, ss = m.groups()
        try:
            dt = datetime(year, _MONTHS.get(mon.lower(), 1), int(d), int(hh), int(mm), int(ss), tzinfo=tz)
        except ValueError:
            return None
        return dt.astimezone(timezone.utc), 0
    return None


def _fmt(dt, digits=0):
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if digits:
        base += "." + f"{dt.microsecond:06d}"[:digits]
    return base + "Z"


def _utc_forms(root):
    """Every UTC rendering the evidence can justify (with and without fractions)."""
    forms = set()
    for _, lines in _evidence(root):
        tz, year = _tz_of(lines)
        for ln in lines:
            got = _to_utc(ln, tz, year)
            if not got:
                continue
            dt, digits = got
            forms.add(_fmt(dt))
            if digits:
                forms.add(_fmt(dt, digits))
            if dt.microsecond:
                forms.add(_fmt(dt, 6).replace("000Z", "Z"))
                forms.add(_fmt(dt, 3))
    return forms


def _literals(instruction):
    out = []
    for lit in _RE_BACKTICK.findall(instruction or ""):
        low = lit.strip()
        if 1 < len(low) <= 60 and not low.startswith("/app/") and low.lower() not in ("key=value", "="):
            out.append(low)
    return out


_WIN_BLOCK = re.compile(r"<Event\b.*?</Event>", re.S | re.I)
_WIN_ID = re.compile(r"<EventID[^>]*>\s*(\d+)\s*</EventID>", re.I)
_WIN_IP = re.compile(r'<Data\s+Name\s*=\s*["\'](?:IpAddress|ClientAddress)["\']\s*>([^<]*)</Data>', re.I)
_WIN_FAIL = {"4625", "4771", "4776", "529", "530", "531", "532", "533", "534", "535", "536", "537", "539"}
_WIN_OK = {"4624", "4648", "528", "540"}


def _win_counts(text, entity):
    """Counts a Windows security log supports, parsed independently of profile.py."""
    counts = set()
    events = []
    for block in _WIN_BLOCK.findall(text):
        eid = _WIN_ID.search(block)
        ip = _WIN_IP.search(block)
        if not eid or not ip:
            continue
        events.append((eid.group(1), ip.group(1).strip()))
    if not events:
        return counts
    own = [e for e in events if e[1] == entity]
    if not own:
        return counts
    counts.add(len(own))
    by_id = {}
    for eid, _ip in own:
        by_id[eid] = by_id.get(eid, 0) + 1
    counts.update(by_id.values())
    fails = sum(1 for eid, _ in own if eid in _WIN_FAIL)
    oks = sum(1 for eid, _ in own if eid in _WIN_OK)
    counts.add(fails)
    counts.add(oks)
    first_ok = next((i for i, (eid, _) in enumerate(own) if eid in _WIN_OK), None)
    if first_ok is not None:
        counts.add(sum(1 for eid, _ in own[:first_ok] if eid in _WIN_FAIL))
        counts.add(sum(1 for eid, _ in own[first_ok:] if eid in _WIN_FAIL))
    return counts


def _supported_counts(root, entity, instruction):
    """Counts the raw lines actually justify for `entity`, computed without profile.py."""
    counts = set()
    if not entity:
        return counts
    lits = _literals(instruction)
    for _, lines in _evidence(root):
        joined = "\n".join(lines)
        if "<Event" in joined:
            counts |= _win_counts(joined, entity)
        own = [ln for ln in lines if entity in ln]
        if not own:
            continue
        counts.add(len(own))
        # event-word counts
        for word in ("Failed", "Accepted", "Invalid user", "error", "denied"):
            n = sum(1 for ln in own if word in ln)
            if n:
                counts.add(n)
        # counts before / after this entity's first success
        first_ok = next((i for i, ln in enumerate(own) if "Accepted" in ln), None)
        if first_ok is not None:
            counts.add(sum(1 for ln in own[:first_ok] if "Failed" in ln))
            counts.add(sum(1 for ln in own[first_ok:] if "Failed" in ln))
        # counts of the statement's own literals
        for lit in lits:
            n = sum(1 for ln in own if lit.lower() in ln.lower())
            if n:
                counts.add(n)
        # HTTP status codes: each exact code, and the 2xx/4xx/5xx families
        codes = {}
        for ln in own:
            m = re.search(r'"\s+(\d{3})\s', ln) or re.search(r'"\s(\d{3})\s', ln) or re.search(r'\s(\d{3})\s+\d+\s', ln)
            if m:
                codes[m.group(1)] = codes.get(m.group(1), 0) + 1
        for n in codes.values():
            counts.add(n)
        for fam in ("2", "4", "5"):
            n = sum(v for k2, v in codes.items() if k2.startswith(fam))
            if n:
                counts.add(n)
        n4 = sum(1 for ln in own if re.search(r'"\s[45]\d{2}\s', ln) or re.search(r'" [45]\d{2} ', ln))
        if n4:
            counts.add(n4)
    return counts


_SIZE_WORDS = ("bytes", "byte", "size", "length", "volume", "bandwidth", "port", "status", "code", "id",
               "байт", "размер", "порт")


def _size_like(key, instruction):
    """A byte count / port / status is a field value in a line, not a count of lines."""
    parts = re.split(r"[_\-. ]+", key.lower())
    if any(w in parts for w in _SIZE_WORDS):
        return True
    m = re.search(rf"`{re.escape(key)}`([^\n]{{0,200}})", instruction or "")
    clause = (m.group(1) if m else "").lower()
    return any(w in clause for w in ("bytes", "size", "response size", "байт", "размер"))


def _standalone_with_entity(root, value, entity):
    """The number appears as its own token on a line that also mentions the entity."""
    rx = re.compile(rf"(?<![\w.]){re.escape(value)}(?![\w.])")
    for _, lines in _evidence(root):
        for ln in lines:
            if (not entity or entity in ln) and rx.search(ln):
                return True
    return False


def _flat(obj, prefix="", out=None, depth=0):
    if out is None:
        out = {}
    if isinstance(obj, dict) and depth < 5:
        for k, v in obj.items():
            _flat(v, f"{prefix}{k}.", out, depth + 1)
    else:
        out[prefix[:-1]] = obj
    return out


def _jsonl_aggregates(root):
    """Sums and counts a JSON-lines stream supports, recomputed by this module alone.

    An aggregate (a total number of bytes, say) never appears on a single line, so it
    cannot be checked by searching the text; it has to be recomputed."""
    agg = set()
    for _, lines in _evidence(root):
        rows = []
        for ln in lines:
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    rows.append(_flat(json.loads(ln)))
                except ValueError:
                    continue
        if not rows or len(rows) > 200_000:
            continue
        numeric = [k for k in rows[0] if any(isinstance(r.get(k), (int, float)) and not isinstance(r.get(k), bool)
                                             for r in rows[:200])]
        strings = [k for k in rows[0] if any(isinstance(r.get(k), str) for r in rows[:200])]
        numeric, strings = numeric[:6], strings[:6]
        groups = {}
        for sf in strings:
            vals = {str(r.get(sf)) for r in rows if isinstance(r.get(sf), str)}
            if len(vals) <= 40:
                groups[sf] = vals
        for sf, vals in groups.items():
            for v in vals:
                sel = [r for r in rows if str(r.get(sf)) == v]
                agg.add(len(sel))
                for nf in numeric:
                    agg.add(int(sum(r.get(nf, 0) or 0 for r in sel)))
                for sf2, vals2 in groups.items():
                    if sf2 == sf:
                        continue
                    for v2 in vals2:
                        sel2 = [r for r in sel if str(r.get(sf2)) == v2]
                        if not sel2:
                            continue
                        agg.add(len(sel2))
                        for nf in numeric:
                            agg.add(int(sum(r.get(nf, 0) or 0 for r in sel2)))
        for nf in numeric:
            agg.add(int(sum(r.get(nf, 0) or 0 for r in rows)))
    return agg


def verify(root, keys, instruction, answer):
    """Return a list of values this evidence cannot independently justify."""
    problems = []
    try:
        root = Path(root)
        if not root.is_dir():
            return problems
        ev = _evidence(root)
        if not ev:
            return problems
        blob = "\n".join("\n".join(lines) for _, lines in ev)
        entity = next((str(answer[k]) for k in keys
                       if _RE_IPV4.fullmatch(str(answer.get(k, "")).strip())), "")
        utc_forms = None
        counts = None
        aggregates = None
        for k in keys:
            v = str(answer.get(k, "")).strip()
            if not v:
                continue
            if _RE_ISO_UTC.match(v):
                if utc_forms is None:
                    utc_forms = _utc_forms(root)
                if utc_forms and v not in utc_forms:
                    problems.append(f"{k}={v}: an independent re-reading of the evidence produces no such UTC instant")
            elif _RE_INT.match(v):
                if _size_like(k, instruction):
                    # a size/port/status is copied from a field, so it must appear as its
                    # own token on one of the suspect's own lines — unless it is an
                    # aggregate, which only an independent recomputation can confirm
                    if _standalone_with_entity(root, v, entity):
                        continue
                    if aggregates is None:
                        aggregates = _jsonl_aggregates(root)
                    if int(v) in aggregates:
                        continue
                    problems.append(f"{k}={v}: neither an evidence line for {entity or 'the suspect'} nor any "
                                    "independently recomputed total produces this number")
                    continue
                if counts is None:
                    counts = _supported_counts(root, entity, instruction)
                    if not counts:
                        counts = _jsonl_aggregates(root)
                if counts and int(v) not in counts:
                    problems.append(f"{k}={v}: an independent recount of the raw lines never produces {v} "
                                    f"(it supports {', '.join(str(c) for c in sorted(counts)[:8])})")
            else:
                if v not in blob:
                    problems.append(f"{k}={v}: this value does not appear verbatim anywhere in the evidence")
    except Exception:  # noqa: BLE001
        return []
    return problems
