"""Zero-token correlation for the structured exfiltration-bundle family.

Recognises only one high-confidence shape (nested JSONL audit rows + edge decisions +
a combined-format proxy log). Anything ambiguous returns None so the model stays in
charge; the result is offered to the model as a preliminary answer to verify.
"""

import ipaddress
import json
import re
from datetime import datetime
from pathlib import Path

EXPECTED_KEYS = {"attacker_ip", "compromised_user", "exfil_bytes", "first_malicious_event_utc"}

_RID_RE = re.compile(r"\brequest_id\s*=\s*([^\s]+)")
_DECISION_RE = re.compile(r"\bdecision\s*=\s*([^\s\"']+)")
_PROXY_RID_RE = re.compile(r"\brid\s*=\s*([^\s]+)")
_PROXY_XFF_RE = re.compile(r'\bxff\s*=\s*"([^"]*)"')
_PROXY_REQ_RE = re.compile(r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})\s+(?P<size>\d+|-)')
_PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def _ts(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _confirmed(root: Path):
    confirmed = set()
    for p in sorted(root.rglob("edge_decisions*.log")) + sorted(root.rglob("*edge*.log")):
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if "CONFIRM" not in line.upper():
                    continue
                m = _RID_RE.search(line)
                d = _DECISION_RE.search(line)
                if m and d and "CONFIRM" in d.group(1).upper():
                    confirmed.add(m.group(1).strip())
        except OSError:
            continue
    return confirmed


def _rows(root: Path):
    for p in sorted(root.rglob("*.jsonl")):
        try:
            with p.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(row, dict):
                        yield row
        except OSError:
            continue


def _magnitude(audit: dict):
    if "payload_logical_bytes" in audit:
        try:
            return int(audit["payload_logical_bytes"])
        except (TypeError, ValueError):
            return None
    try:
        return int(audit.get("bytes"))
    except (TypeError, ValueError):
        return None


def _logical_proxy_lines(p: Path):
    cur = None
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        if raw[:1] in ("\t", " ") and cur is not None:
            cur += " " + raw.strip()
            continue
        if cur is not None:
            yield cur
        s = raw.strip()
        cur = None if (not s or s.startswith("#")) else s
    if cur is not None:
        yield cur


def _public_client(xff: str):
    for seg in reversed(xff.split(",")):
        v = seg.strip()
        if not v or v.lower() == "unknown":
            continue
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            continue
        if isinstance(ip, ipaddress.IPv4Address) and any(ip in n for n in _PRIVATE):
            continue
        return str(ip)
    return None


def solve(evidence_dir) -> dict:
    """Return the four fields plus `_detail` for the briefing, or None."""
    root = Path(evidence_dir)
    if not root.is_dir():
        return None
    confirmed = _confirmed(root)
    if not confirmed:
        return None
    cands = []
    for row in _rows(root):
        audit, http, ident = row.get("audit"), row.get("http"), row.get("identity")
        if not all(isinstance(x, dict) for x in (audit, http, ident)):
            continue
        if str(audit.get("event", "")).lower() != "sensitive_export":
            continue
        rid = str(http.get("request_id", "")).strip()
        if rid not in confirmed:
            continue
        ts = _ts(row.get("ts"))
        mag = _magnitude(audit)
        if ts is None or mag is None:
            continue
        cands.append((mag, ts, rid, row))
    if not cands:
        return None
    max_mag = max(c[0] for c in cands)
    tied = [c for c in cands if c[0] == max_mag]
    tied.sort(key=lambda c: c[1])
    mag, ts, rid, row = tied[-1]
    attacker = None
    proxy_line = ""
    wire = row["audit"].get("bytes")
    for p in sorted(root.rglob("proxy*.log")) + sorted(root.rglob("*access*.log")):
        for line in _logical_proxy_lines(p):
            m = _PROXY_RID_RE.search(line)
            if not m or m.group(1).strip() != rid:
                continue
            x = _PROXY_XFF_RE.search(line)
            if not x:
                continue
            req = _PROXY_REQ_RE.search(line)
            if "transport" in row["audit"] and req is not None:
                if req.group("status") != "200" or (req.group("size") != "-" and str(wire) != req.group("size")):
                    continue
            client = _public_client(x.group(1))
            if client:
                attacker = client
                proxy_line = line
                break
        if attacker:
            break
    if not attacker:
        return None
    return {
        "attacker_ip": attacker,
        "compromised_user": str(row["identity"].get("subject", "")),
        "exfil_bytes": str(mag),
        "first_malicious_event_utc": str(row.get("ts")),
        "_detail": f"selected audit record: {json.dumps(row, ensure_ascii=False)[:600]}\nmatching proxy line: {proxy_line[:400]}",
    }
