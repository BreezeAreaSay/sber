"""A written incident report, composed from the deterministic log profiles.

Some forensics tasks do not ask for `key=value` lines but for a report in prose: what
happened, who did it, when, and what it means. That phrasing lands in the generic bucket
where only the model could answer, so a weak or unreachable model left the disk empty.

Everything here is derived from the same structured facts the key=value seed uses, so
the narrative states only what the evidence supports: the source that stands out, the
account it reached, the times converted to UTC, and the log lines themselves.
"""

import re
from pathlib import Path

from acpagent import profile

_ATTACK_WORD = {
    "auth": "a credential-guessing campaign against the host's authentication service",
    "access": "malicious HTTP requests against the web service",
}


_ISO_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")


def _utc(line, facts):
    """Just the UTC instant: the section headings already say the zone."""
    note = profile.utc_note(line, facts.get("tz"), facts.get("label"), facts.get("year")) or ""
    m = _ISO_Z.search(note)
    return m.group(0) if m else ""


def _suspect(facts_list):
    """(facts, ip, record, kind) for the source the evidence points at."""
    best = None
    for f in facts_list:
        per_ip = f.get("per_ip") or {}
        for ip, rec in per_ip.items():
            if f["kind"] == "auth":
                score = rec["failed"] * 2 + rec["invalid"] + (500 if rec["first_accept"] and rec["failed_before"] else 0)
            else:
                score = rec.get("severe", 0) * 20 + rec.get("sus", 0)
            if score <= 0:
                continue
            if best is None or score > best[0]:
                best = (score, f, ip, rec, f["kind"])
    return best[1:] if best else None


def build(evidence_root, instruction: str = "") -> str:
    """A Markdown incident report, or "" when the evidence supports no story."""
    root = Path(evidence_root)
    try:
        facts_list = profile.dir_facts(root)
    except Exception:  # noqa: BLE001
        return ""
    picked = _suspect(facts_list)
    if picked is None:
        return ""
    facts, ip, rec, kind = picked
    src_name = Path(facts["path"]).name
    out = ["# Incident report", ""]

    # --- summary -------------------------------------------------------------------
    compromised_account = None
    if kind == "auth" and rec.get("first_accept"):
        line, user, ev_kind, _order = rec["first_accept"]
        compromised_account = user
        when = _utc(line, facts)
        out += [
            "## Summary", "",
            f"The evidence in `{src_name}` records {_ATTACK_WORD['auth']} originating from "
            f"**{ip}**. The source made {rec['failed']} failed authentication attempts, "
            f"{rec['failed_before']} of them before it finally succeeded, and then logged in "
            f"successfully as **{user}**"
            + (f" at **{when}**" if when else "") + ".", "",
        ]
    elif kind == "auth":
        out += [
            "## Summary", "",
            f"The evidence in `{src_name}` records {_ATTACK_WORD['auth']} originating from "
            f"**{ip}**, with {rec['failed']} failed authentication attempts. No successful "
            "login from that source appears in the log.", "",
        ]
    else:
        first_sus = rec.get("first_sus")
        when = _utc(first_sus, facts) if first_sus else ""
        served = rec.get("first_sus_ok")
        out += [
            "## Summary", "",
            f"The evidence in `{src_name}` records {_ATTACK_WORD['access']} originating from "
            f"**{ip}**. That client sent {rec['n']} requests in total, of which "
            f"{rec.get('sus', 0)} carried attack payloads"
            + (f" (first at **{when}**)" if when else "")
            + (", and at least one of them was answered with HTTP 200, so the attempt succeeded."
               if served else ", none of which were answered successfully.") + "", "",
        ]

    # --- what the evidence says ----------------------------------------------------
    out += ["## Findings", ""]
    out.append(f"- **Source address:** `{ip}`")
    if kind == "auth":
        out.append(f"- **Failed authentication attempts:** {rec['failed']} "
                   f"({rec['failed_before']} before the first success)")
        if rec.get("users"):
            tried = ", ".join(f"`{u}` ({c})" for u, c in rec["users"].most_common(6))
            out.append(f"- **Accounts targeted:** {tried}")
        if compromised_account:
            out.append(f"- **Compromised account:** `{compromised_account}`")
            out.append(f"- **Time of the successful login (UTC):** {_utc(rec['first_accept'][0], facts) or 'see the log line below'}")
    else:
        out.append(f"- **Requests from this client:** {rec['n']} ({rec.get('err', 0)} answered 4xx/5xx)")
        out.append(f"- **Requests carrying an attack payload:** {rec.get('sus', 0)}")
        if rec.get("first_sus"):
            out.append(f"- **First attack request (UTC):** {_utc(rec['first_sus'], facts) or 'see below'}")
        if rec.get("first_sus_ok"):
            parsed = {q["line"]: q for q in rec.get("parsed", [])}
            got = parsed.get(rec["first_sus_ok"], {})
            if got.get("path"):
                out.append(f"- **Resource disclosed (first attack answered 2xx):** `{got['path']}`")
        top = ", ".join(f"`{q}` ({c})" for q, c in rec["paths"].most_common(5))
        if top:
            out.append(f"- **Most requested paths:** {top}")
    out.append("")

    # --- timeline ------------------------------------------------------------------
    events = []
    if kind == "auth":
        if rec.get("first_failed"):
            events.append((_utc(rec["first_failed"], facts), "first failed authentication attempt from this source"))
        if rec.get("first_accept"):
            events.append((_utc(rec["first_accept"][0], facts), f"successful login as `{rec['first_accept'][1]}`"))
        if rec.get("last"):
            events.append((_utc(rec["last"], facts), "last recorded activity from this source"))
    else:
        if rec.get("first"):
            events.append((_utc(rec["first"], facts), "first request from this client"))
        if rec.get("first_sus"):
            events.append((_utc(rec["first_sus"], facts), "first request carrying an attack payload"))
        if rec.get("first_sus_ok"):
            events.append((_utc(rec["first_sus_ok"], facts), "first attack request answered with HTTP 200"))
        if rec.get("last"):
            events.append((_utc(rec["last"], facts), "last request from this client"))
    events = [(t, d) for t, d in events if t]
    if events:
        out += ["## Timeline (UTC)", "", "| Time (UTC) | Event |", "| --- | --- |"]
        seen = set()
        for t, d in events:
            if (t, d) in seen:
                continue
            seen.add((t, d))
            out.append(f"| {t} | {d} |")
        out.append("")

    # --- evidence ------------------------------------------------------------------
    lines = []
    if kind == "auth":
        if rec.get("first_failed"):
            lines.append(rec["first_failed"])
        if rec.get("first_accept"):
            lines.append(rec["first_accept"][0])
    else:
        for key in ("first_sus", "first_sus_ok"):
            if rec.get(key):
                lines.append(rec[key])
    for extra in (rec.get("lines") or [])[:4]:
        if extra not in lines:
            lines.append(extra)
    if lines:
        out += ["## Evidence", "",
                f"Log lines from `{src_name}` (timestamps as recorded; UTC conversions above):", "", "```"]
        out += [ln[:300] for ln in lines[:8]]
        out += ["```", ""]

    # --- impact and response --------------------------------------------------------
    out += ["## Impact", ""]
    if kind == "auth" and compromised_account:
        out.append(f"The attacker obtained interactive access as `{compromised_account}`. Everything that account "
                   "can reach must be treated as exposed, and any action taken after the login above "
                   "should be considered attacker-controlled until proven otherwise.")
    elif kind == "auth":
        out.append("No successful authentication is recorded, so the attempt appears to have failed. "
                   "The source was nevertheless able to make repeated authentication attempts unthrottled.")
    else:
        out.append("The client was able to submit crafted requests against the service. Where such a "
                   "request was answered with HTTP 200, the corresponding resource must be treated as "
                   "disclosed to the attacker.")
    out += ["", "## Recommended actions", "",
            f"- Block traffic from `{ip}` and review anything else it touched.",
            "- Rotate the credentials of every account named above, and any secret those accounts could read.",
            "- Rate-limit and alert on repeated authentication failures from one source."
            if kind == "auth" else
            "- Validate and contain the parameters used by the affected endpoint, and review access logs for other clients using the same payloads.",
            "- Preserve the evidence files referenced here for the full investigation.", ""]
    return "\n".join(out)
