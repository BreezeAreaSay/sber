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
            if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
                d, _ = pcap_digest(p)
                if d:
                    block = f"## {os.path.relpath(p, root)} (packet capture)\n{d[:PER_FILE_CHARS * 2]}"
                    parts.append(block)
                    total += len(block)
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


# ---- pcap / pcapng --------------------------------------------------------------------------

import struct

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")


def _iter_pcap_packets(data: bytes):
    """Yield raw link-layer frames from a pcap or pcapng buffer (best effort)."""
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        end = "<" if little else ">"
        linktype = struct.unpack(end + "I", data[20:24])[0]
        off = 24
        n = 0
        while off + 16 <= len(data) and n < 200_000:
            _, _, incl, _ = struct.unpack(end + "IIII", data[off:off + 16])
            off += 16
            yield linktype, data[off:off + incl]
            off += incl
            n += 1
        return
    if magic == b"\x0a\x0d\x0d\x0a":  # pcapng
        off = 0
        little = True
        linktype = 1
        n = 0
        while off + 12 <= len(data) and n < 200_000:
            btype = struct.unpack("<I", data[off:off + 4])[0]
            if btype == 0x0A0D0D0A:
                bom = data[off + 8:off + 12]
                little = bom == b"\x4d\x3c\x2b\x1a"
            end = "<" if little else ">"
            blen = struct.unpack(end + "I", data[off + 4:off + 8])[0]
            if blen < 12 or off + blen > len(data):
                break
            if btype == 0x00000001:  # interface description
                linktype = struct.unpack(end + "H", data[off + 8:off + 10])[0]
            elif btype == 0x00000006:  # enhanced packet block
                caplen = struct.unpack(end + "I", data[off + 20:off + 24])[0]
                yield linktype, data[off + 28:off + 28 + caplen]
                n += 1
            elif btype == 0x00000003:  # simple packet block
                plen = struct.unpack(end + "I", data[off + 8:off + 12])[0]
                yield linktype, data[off + 12:off + 12 + plen]
                n += 1
            off += blen
        return


def _parse_ip(frame: bytes, linktype: int):
    """Return (src, dst, proto, sport, dport, payload) or None."""
    if linktype == 1:  # ethernet
        if len(frame) < 14:
            return None
        et = struct.unpack("!H", frame[12:14])[0]
        off = 14
        if et == 0x8100 and len(frame) >= 18:
            et = struct.unpack("!H", frame[16:18])[0]
            off = 18
        if et != 0x0800:
            return None
    elif linktype == 101:  # raw ip
        off = 0
    elif linktype == 113:  # linux cooked
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        off = 16
    else:
        return None
    ip = frame[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    proto = ip[9]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tp = ip[ihl:]
    sport = dport = 0
    payload = b""
    if proto == 6 and len(tp) >= 20:
        sport, dport = struct.unpack("!HH", tp[:4])
        doff = (tp[12] >> 4) * 4
        payload = tp[doff:]
    elif proto == 17 and len(tp) >= 8:
        sport, dport = struct.unpack("!HH", tp[:4])
        payload = tp[8:]
    return src, dst, proto, sport, dport, payload


def pcap_digest(path: Path, max_bytes: int = 60_000_000):
    """Summary text for a capture file plus the printable payload strings (for flag scans)."""
    try:
        if path.stat().st_size > max_bytes:
            return "", b""
        data = path.read_bytes()
    except OSError:
        return "", b""
    flows = Counter()
    talkers = Counter()
    protos = Counter()
    strings = []
    total = 0
    payload_blob = []
    for linktype, frame in _iter_pcap_packets(data):
        total += 1
        parsed = _parse_ip(frame, linktype)
        if not parsed:
            continue
        src, dst, proto, sport, dport, payload = parsed
        pname = {6: "tcp", 17: "udp", 1: "icmp"}.get(proto, str(proto))
        protos[pname] += 1
        talkers[src] += 1
        flows[f"{src} -> {dst}:{dport}/{pname}"] += 1
        if payload:
            payload_blob.append(payload)
            for m in _PRINTABLE_RUN.finditer(payload[:2000]):
                s = m.group(0).decode("ascii", "replace")
                if re.search(r"flag|key|pass|user|login|token|secret|GET |POST |HTTP/|Host:|Authorization|Cookie|ctf|\{", s, re.I):
                    strings.append(s[:160])
    if not total:
        return "", b""
    out = [f"capture: {total} packets; protocols: {_top(protos, 5)}",
           f"top talkers: {_top(talkers, 8)}",
           f"top flows: {_top(flows, 10)}"]
    uniq = []
    seen = set()
    for s in strings:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    if uniq:
        out.append("interesting payload strings:\n  " + "\n  ".join(uniq[:30]))
    return "\n".join(out), b"\n".join(payload_blob)[:5_000_000]
