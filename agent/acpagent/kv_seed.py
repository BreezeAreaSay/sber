"""Generic deterministic answer seed for key=value forensics tasks.

The statement of such a task names a small set of keys (attacker IP, compromised
account, first-success time in UTC, a count of failed attempts, a leaked path ...) and
defines each one in a clause next to the key name.  The log profiles (profile.py)
already hold every fact those clauses refer to; this module maps each key to the
matching fact by the words of its clause, so the answer file exists before the model
runs and the model only has to confirm it against the evidence.

Nothing here is specific to one dataset: the suspect is chosen from the evidence
(the client with the attack payloads the statement names, or the source that
succeeded after failing), and every value is copied from a real log line.
"""

import re
from pathlib import Path

from acpagent import profile

_KEY_CLAUSE_RE = re.compile(r"`(?P<key>[A-Za-z_][A-Za-z0-9_]*)`\s*[-—–:]*\s*(?P<clause>[^\n]{0,400})")
_LITERAL_RE = re.compile(r"`([^`\n]{1,60})`")
_ISO_FORMAT_RE = re.compile(r"YYYY-MM-DD[T ]HH:MM:SS(?P<frac>\.s+|\.SSS|\.fff)?Z?", re.I)
_ATTACK_LITERALS = ("../", "..\\", "%2e%2e", "/etc/passwd", "union", "select", "' or", "<script", "cmd=", "$(", "`",
                    "sleep(", "/.env", "/.git", "wp-admin", "shadow", "passwd", "%00", "..%2f", "etc/", "config")
_COUNT_WORDS = ("count", "attempts", "attempt", "number", "num", "total", "requests", "events", "lines", "n", "hits", "tries",
                "failures", "failed", "logins", "entries", "records", "количество", "число", "попыток")
_TIME_WORDS = ("utc", "time", "timestamp", "ts", "when", "date", "datetime", "время", "дата")
_ORDINAL_WORDS = ("first", "last", "start", "earliest", "latest", "at")
_IP_WORDS = ("ip", "addr", "address", "source", "src", "client", "host", "origin", "remote", "адрес")
_USER_WORDS = ("account", "user", "username", "login", "principal", "subject", "actor", "identity", "учетн", "аккаунт",
               "пользовател", "логин")
_PATH_WORDS = ("file", "path", "url", "uri", "resource", "endpoint", "leaked", "target", "page", "файл", "путь")
_BYTES_WORDS = ("bytes", "size", "volume", "length", "байт", "размер")
_ID_WORDS = ("id", "rid", "request_id", "session", "trace", "uuid")


_RU_CUES = (("перв", "first"), ("послед", "last"), ("успеш", "success"), ("до ", "before"), ("перед", "before"),
            ("неудач", "failed"), ("ошиб", "error"), ("всего", "total"), ("путь", "path"), ("файл", "file"),
            ("байт", "bytes"), ("сколько", "how many"), ("количество", "how many"), ("число", "number of"),
            ("учетн", "account"), ("пользовател", "user"), ("врем", "time"), ("метк", "timestamp"), ("адрес", "address"),
            ("целое", "(integer)"), ("без строки запроса", "without the query"), ("параметр", "parameter"),
            ("вернул", "returned"), ("отвеч", "returned"), ("утеч", "leak"), ("скомпромет", "compromis"))


def _with_english_cues(clause: str) -> str:
    extra = [en for ru, en in _RU_CUES if ru in clause]
    return clause + (" " + " ".join(extra) if extra else "")


def _xff_client(ln: str):
    m = profile._XFF_RE.search(ln)
    if not m:
        return None
    chain = [h.strip() for h in (m.group(1) or m.group(2) or "").split(",") if h.strip()]
    public = [h for h in chain if profile._IPV4.fullmatch(h) and not profile._is_private(h)]
    return public[-1] if public else None


def _parts(key: str):
    return [p for p in re.split(r"[_\-. ]+", key.lower()) if p]


def _clauses(instruction: str, keys):
    """key -> the statement's own words next to that key (lower-cased)."""
    out = {}
    for m in _KEY_CLAUSE_RE.finditer(instruction or ""):
        k = m.group("key")
        if k in keys and k not in out:
            out[k] = _with_english_cues(m.group("clause").lower())
    for k in keys:
        if k not in out:
            # fall back to the line that mentions the key without backticks
            m = re.search(rf"(?im)^.*\b{re.escape(k)}\b.*$", instruction or "")
            out[k] = _with_english_cues(m.group(0).lower()) if m else ""
    return out


def _attack_literals(text: str):
    """Backticked literals in the statement that describe the attack traffic."""
    found = []
    for lit in _LITERAL_RE.findall(text or ""):
        low = lit.lower().strip()
        if len(low) < 2 or low in ("=", "key=value", "yyyy-mm-ddthh:mm:ssz") or low.startswith("/app/"):
            continue
        identifier = low.replace("_", "").isalnum() and low.isidentifier()
        keyword = lit.strip().isupper() or low in _ATTACK_LITERALS   # `UNION`, `passwd`
        if identifier and not keyword:
            continue  # key names / identifiers
        if keyword or any(a in low for a in _ATTACK_LITERALS) or not low.isalnum():
            if lit not in found:
                found.append(lit)
    return found


def _line_utc(ln: str, facts, keep_fraction: bool, seconds_only: bool):
    dt = profile.parse_ts(ln, facts.get("tz"), facts.get("year"))
    if dt is None:
        return None
    if seconds_only:
        return profile.fmt_utc(dt, keep_fraction=False)
    digits = profile._fraction_digits(ln)
    if digits and keep_fraction:
        return profile.fmt_utc(dt, digits=digits)
    return profile.fmt_utc(dt, keep_fraction=keep_fraction)


def _raw_ts(ln: str):
    m = profile._ISO_RE.search(ln) or profile._CLF_TS_RE.search(ln)
    if m:
        return m.group(0).strip("[]")
    m = profile._SYSLOG_RE.match(ln)
    return f"{m.group('mon')} {m.group('day')} {m.group('time')}" if m else None


def _count_lines(lines, literals):
    if not literals:
        return None
    return sum(1 for ln in lines if any(l.lower() in ln.lower() for l in literals))


def _pick_source(facts_list, instruction: str):
    """Choose the evidence file and suspect the statement is about."""
    low = (instruction or "").lower()
    web_words = ("http", "web", "nginx", "apache", "access.log", "request", "traversal", "url", "path", "get /", "proxy", "browser")
    auth_words = ("ssh", "brute", "password", "login", "auth.log", "sshd", "account", "credential", "accepted")
    web_score = sum(w in low for w in web_words)
    auth_score = sum(w in low for w in auth_words)
    literals = _attack_literals(instruction)
    candidates = []
    for f in facts_list:
        if f["kind"] == "access":
            for ip, r in f["per_ip"].items():
                hits = _count_lines(r["lines"], literals) if literals else None
                score = (hits or 0) * 10 + r["severe"] * 3 + r["sus"]
                if (hits or 0) == 0 and r["severe"] == 0:
                    continue
                candidates.append((score + (5 if web_score >= auth_score else 0), "access", f, ip, r, hits))
        elif f["kind"] == "auth":
            for ip, r in f["per_ip"].items():
                success_after_fail = r["first_accept"] is not None and r["failed_before"] > 0
                score = (r["failed_before"] * 2 if success_after_fail else 0) + r["failed"] + r["invalid"]
                if r["failed"] == 0 and r["invalid"] == 0:
                    continue
                candidates.append((score + (5 if auth_score > web_score else 0) + (50 if success_after_fail else 0), "auth", f, ip, r, None))
    if not candidates:
        return None
    candidates.sort(key=lambda c: -c[0])
    best = candidates[0]
    # the suspect must stand out: a runner-up with a comparable score means the choice
    # is a coin flip and the seed would only mislead
    runner = candidates[1][0] if len(candidates) > 1 else 0
    if runner and best[0] < runner * 1.5 and candidates[1][3] != best[3]:
        return None
    return best


def _first(lines, pred):
    for ln in lines:
        if pred(ln):
            return ln
    return None


def solve(root, keys, instruction: str):
    """Return (seed dict with '_detail' text, confidence dict) or (None, {})."""
    keys = list(keys)
    if not keys:
        return None, {}
    facts_list = profile.dir_facts(Path(root))
    if not facts_list:
        return None, {}
    src = _pick_source(facts_list, instruction)
    if src is None:
        return None, {}
    _, kind, facts, ip, rec, hits = src
    literals = _attack_literals(instruction)
    clauses = _clauses(instruction, keys)
    seed, conf, detail = {}, {}, []
    lines = rec["lines"]

    def mark(ln, facts):
        return f"{ln[:160]}{profile.utc_note(ln, facts.get('tz'), facts.get('label'), facts.get('year'))}"

    # attack lines of the suspect: the statement's literals first, then the generic payload scan
    if kind == "access":
        if literals:
            attack = [ln for ln in lines if any(l.lower() in ln.lower() for l in literals)]
        else:
            attack = [ln for ln in lines if profile._SEVERE.search(ln)] or [ln for ln in lines if profile._SUSPICIOUS.search(ln)]
        parsed_by_line = {p["line"]: p for p in rec["parsed"]}
    else:
        attack = [ln for ln in lines if "Failed" in ln or "Invalid user" in ln]
        parsed_by_line = {}
    if not attack:
        return None, {}

    def ts_value(ln, wants_utc, keep_fraction, seconds_only):
        return _line_utc(ln, facts, keep_fraction, seconds_only) if wants_utc else _raw_ts(ln)

    first_ok = _first(attack, lambda l: parsed_by_line.get(l, {}).get("status", "").startswith("2")) if kind == "access" else None

    for k in keys:
        parts = _parts(k)
        clause = clauses.get(k, "")
        # the key name decides the type; the clause only decides it for a name that says
        # nothing (e.g. `answer`), and ordinal words (first/last) alone mean a time
        by_name = None
        for label, words in (("ip", _IP_WORDS), ("user", _USER_WORDS), ("count", _COUNT_WORDS), ("bytes", _BYTES_WORDS),
                             ("path", _PATH_WORDS), ("time", _TIME_WORDS), ("id", _ID_WORDS), ("time", _ORDINAL_WORDS)):
            if any(w in parts for w in words) or (label == "ip" and k.lower().endswith("ip")):
                by_name = label
                break
        if by_name is None:
            if "how many" in clause or "(integer)" in clause or "number of" in clause or "count of" in clause:
                by_name = "count"
            elif "timestamp" in clause or "utc" in clause or " time " in f" {clause} ":
                by_name = "time"
            elif " ip " in f" {clause} " or "address" in clause:
                by_name = "ip"
            elif any(w in clause for w in ("username", "account", " user ")):
                by_name = "user"
            elif any(w in clause for w in ("path", "file", "url")):
                by_name = "path"
        is_ip, is_user, is_time = by_name == "ip", by_name == "user", by_name == "time"
        is_count, is_path, is_bytes, is_id = by_name == "count", by_name == "path", by_name == "bytes", by_name == "id"
        value, why, c, src_line = None, "", "low", None
        # order matters: 'first_attack_utc' is a time even though 'attack' is not a time word,
        # 'attacker_ip' is an IP even though 'first' may appear in its clause.
        if is_ip:
            value, why, c, src_line = ip, "the client/source that produced the attack traffic", "high", attack[0]
            low_all = (instruction or "").lower()
            if kind == "access" and ("xff" in clause or "x-forwarded" in clause or "xff" in low_all or "x-forwarded" in low_all):
                xff = _xff_client(attack[0])
                if xff:
                    value, why = xff, "last public hop of the X-Forwarded-For chain of the attack requests"
                else:
                    c = "low"
        elif is_count:
            own = [l for l in _attack_literals(clause) if any(l.lower() in ln.lower() for ln in lines)]
            if kind == "auth":
                if "before" in clause and any(w in clause for w in ("success", "accepted", "login")):
                    value, why, c = str(rec["failed_before"]), "Failed lines from that IP before its first Accepted line", "high"
                elif any(w in clause for w in ("fail", "unsuccessful", "wrong", "rejected", "неудач")):
                    value, why, c = str(rec["failed"]), "Failed lines from that IP (whole file)", "high"
                elif "invalid" in clause:
                    value, why, c = str(rec["invalid"]), "Invalid user lines from that IP", "high"
                else:
                    value, why, c = str(rec["failed"]), "Failed lines from that IP (default reading)", "low"
            else:
                if own:
                    value, why, c = str(_count_lines(lines, own)), f"requests from that client containing {', '.join(own)}", "high"
                elif any(w in clause for w in ("4xx", "404", "403", "error", "denied", "failed")):
                    value, why, c = str(rec["err"]), "4xx/5xx responses to that client", "high"
                elif any(w in clause for w in ("total", "all requests", "every request", "all its requests")):
                    value, why, c = str(rec["n"]), "all requests from that client", "high"
                elif literals:
                    value, why, c = str(len(attack)), f"requests from that client containing {', '.join(literals)}", "high" if len(literals) == 1 else "low"
                else:
                    value, why, c = str(len(attack)), "requests from that client with an attack payload (code scan)", "low"
        elif is_time:
            wants_utc = "utc" in parts or "utc" in clause
            fm = _ISO_FORMAT_RE.search(clause) or _ISO_FORMAT_RE.search(instruction or "")
            seconds_only = bool(fm and not fm.group("frac"))
            keep_fraction = not seconds_only
            if kind == "auth":
                if any(w in clause for w in ("success", "accepted", "logged in", "compromis", "successful")) and rec["first_accept"]:
                    src_line = (rec["first_accept_pw"] or rec["first_accept"])[0] if "password" in clause else rec["first_accept"][0]
                    why, c = "first Accepted line of that IP", "high"
                elif "last" in clause:
                    src_line, why, c = rec["last"], "last event of that IP", "high"
                else:
                    src_line = rec["first_failed"] or rec["first"]
                    why, c = "first Failed line of that IP", "high" if "first" in clause else "low"
            else:
                if "last" in clause and "first" not in clause:
                    src_line, why, c = attack[-1], "last attack request of that client", "high"
                elif any(w in clause for w in ("200", "2xx", "succe", "returned")) and "first" in clause:
                    src_line = first_ok or attack[0]
                    why, c = "first attack request answered 2xx", "high" if first_ok else "low"
                else:
                    src_line = attack[0]
                    why, c = "first attack request of that client", "high" if ("first" in clause or "first" in parts) else "low"
            value = ts_value(src_line, wants_utc, keep_fraction, seconds_only) if src_line else None
        elif is_user:
            if kind == "auth":
                if rec["first_accept"] and (any(w in clause for w in ("success", "logged", "compromis", "accepted")) or not rec["users"]):
                    value, why, c, src_line = rec["first_accept"][1], "account of that IP's first Accepted line", "high", rec["first_accept"][0]
                elif rec["users"]:
                    value, why, c = rec["users"].most_common(1)[0][0], "account most often tried from that IP", "low"
            elif rec["users"]:
                value, why, c = rec["users"].most_common(1)[0][0], "authenticated user of that client's requests", "low"
        elif is_path and kind == "access":
            if any(w in clause for w in ("200", "2xx", "succe", "returned", "served", "disclosed", "leak")) and first_ok:
                src_line, why, c = first_ok, "path of the first attack request answered 2xx", "high"
            else:
                src_line, why, c = attack[0], "path of the first attack request", "high" if "first" in clause else "low"
            value = parsed_by_line.get(src_line, {}).get("path")
            if value and any(w in clause for w in ("basename", "file name only", "filename only")):
                value = value.rsplit("/", 1)[-1]
            elif value and any(w in clause for w in ("without the query", "without query", "path only", "no query string", "before the ?", "before '?'")):
                value = value.split("?", 1)[0]
            elif value and any(w in clause for w in ("query string only", "the query string", "the parameter value", "value of the")):
                if "?" in value and ("parameter value" in clause or "value of the" in clause):
                    value = value.split("?", 1)[1].split("=", 1)[-1].split("&")[0]
                elif "?" in value:
                    value = value.split("?", 1)[1]
        elif is_bytes and kind == "access":
            if any(w in clause for w in ("200", "2xx", "leak", "disclos", "response", "served")) and "total" not in clause and first_ok:
                src_line, why, c = first_ok, "response size of the first attack request answered 2xx", "high"
                value = parsed_by_line[first_ok]["size"]
            else:
                value, why, c = str(rec["bytes"]), "bytes served to that client (all requests)", "low"
        elif is_id:
            continue
        if value is None or value == "" or value == "-":
            continue
        seed[k] = str(value)
        conf[k] = c
        detail.append(f"- {k}={value}  ({why}" + (f"; source line: {mark(src_line, facts)}" if src_line else "") + ")")
    if not seed:
        return None, {}
    header = (f"Derived from {facts['path'].name} ({kind} log; suspect {ip}: " +
              (f"{len(attack)} attack requests" if kind == "access" else f"{rec['failed']} failed logins, first success {'yes' if rec['first_accept'] else 'no'}") + "):")
    seed["_detail"] = header + "\n" + "\n".join(detail)
    return seed, conf
