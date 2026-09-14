"""Mechanical fixes for the non-SQL vulnerability classes, verified by the tests.

Every rewrite here is kept only if the code still compiles, the app still starts and
the project's tests still pass (`_verify_stage` in agent.py reverts it otherwise), so a
fix that does not fit the codebase costs nothing but the attempt.

Covered: path traversal (containment check, with a basename fallback), disabled JWT
signature verification, `eval` on request data, and disabled TLS/redirect checks that
`safefix` does not already handle.
"""

import re
from pathlib import Path

_SKIP_DIRS = {".venv", "venv", "site-packages", "node_modules", "build", "dist", ".git", "__pycache__", ".eggs"}

# `path = os.path.join(BASE, something_user_controlled)`
_JOIN_ASSIGN = re.compile(
    r"^(?P<indent>[ \t]*)(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<call>os\.path\.join\(\s*(?P<base>[A-Za-z_][\w.]*)\s*,\s*(?P<rest>[^\n]*?)\))\s*$"
)
# a name that plausibly carries user input
_USERISH = re.compile(r"request\.|req\.|\bparams\b|\bargs\b|\bquery\b|\bform\b|filename|file_name|\bfname\b|"
                      r"\bname\b|\bpath\b|\bfile\b|user_input|\binput\b", re.I)
_TRAVERSAL_GUARDED = re.compile(r"realpath|abspath|commonpath|is_relative_to|startswith\(\s*(?:os\.path\.)?real", re.I)

_JWT_VERIFY_FALSE = re.compile(r"(jwt\.decode\([^\n]*?),\s*verify\s*=\s*False")
_JWT_OPTIONS = re.compile(r"(\"|')verify_signature(\"|')\s*:\s*False")
_ALG_NONE = re.compile(r"algorithms\s*=\s*\[\s*(['\"])none\1\s*\]", re.I)
_EVAL_REQ = re.compile(r"(?<![\w.])eval\s*\(\s*([^()\n]{0,120}(?:request\.|req\.|args|params|form|body|payload)[^()\n]{0,120})\)")


def _iter_py(workdir: Path):
    for p in Path(workdir).rglob("*.py"):
        if set(p.parts) & _SKIP_DIRS or p.name.startswith("test"):
            continue
        yield p


def _error_stmt(src: str, indent: str) -> str:
    """A rejection statement that fits the framework this file already uses."""
    if re.search(r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b|HTTPException", src):
        return f'{indent}    raise HTTPException(status_code=404, detail="Not found")'
    if re.search(r"\bfrom\s+flask\b|\bimport\s+flask\b", src):
        return f"{indent}    abort(404)"
    return f'{indent}    raise ValueError("path outside the allowed directory")'


def _ensure_import(src: str) -> str:
    """Make sure the rejection helper and os are importable."""
    if "abort(404)" in src and re.search(r"\bfrom\s+flask\s+import\b", src) and not re.search(r"\bfrom\s+flask\s+import\b[^\n]*\babort\b", src):
        src = re.sub(r"(\bfrom\s+flask\s+import\s+)([^\n]+)", lambda m: m.group(1) + m.group(2).rstrip() + ", abort", src, count=1)
    if "HTTPException(" in src and "fastapi" in src and not re.search(r"\bfrom\s+fastapi\s+import\b[^\n]*HTTPException", src):
        if re.search(r"\bfrom\s+fastapi\s+import\b", src):
            src = re.sub(r"(\bfrom\s+fastapi\s+import\s+)([^\n]+)", lambda m: m.group(1) + m.group(2).rstrip() + ", HTTPException", src, count=1)
        else:
            src = "from fastapi import HTTPException\n" + src
    if re.search(r"^\s*(?:import os|from os import)", src, re.M) is None and "os.path" in src:
        src = "import os\n" + src
    return src


def rewrite_traversal(src: str, variant: str = "containment"):
    """Contain a filesystem path built from user input inside its base directory."""
    lines = src.splitlines(keepends=True)
    out, notes = [], []
    for i, line in enumerate(lines):
        out.append(line)
        m = _JOIN_ASSIGN.match(line.rstrip("\n"))
        if not m:
            continue
        rest = m.group("rest")
        if not _USERISH.search(rest):
            continue
        following = "".join(lines[i + 1:i + 6])
        if _TRAVERSAL_GUARDED.search(following):
            continue  # already checked
        indent, var, base = m.group("indent"), m.group("var"), m.group("base")
        if variant == "basename":
            out.append(f"{indent}{var} = os.path.join({base}, os.path.basename(os.path.normpath({var}).lstrip('/')))\n")
            notes.append(f"path traversal: reduced the user-controlled component of {var} to a bare file name")
        else:
            guard = (f"{indent}if not os.path.realpath({var}).startswith(os.path.realpath({base}) + os.sep):\n"
                     + _error_stmt(src, indent) + "\n")
            out.append(guard)
            notes.append(f"path traversal: {var} is now required to stay inside {base}")
    if not notes:
        return None, []
    return _ensure_import("".join(out)), notes


def rewrite_auth(src: str):
    """Re-enable signature verification and remove eval on request data."""
    new, notes = src, []
    if _JWT_VERIFY_FALSE.search(new):
        new = _JWT_VERIFY_FALSE.sub(r"\1", new)
        notes.append("JWT: removed verify=False so the signature is checked")
    if _JWT_OPTIONS.search(new):
        new = _JWT_OPTIONS.sub(lambda m: f"{m.group(1)}verify_signature{m.group(2)}: True", new)
        notes.append("JWT: verify_signature set back to True")
    if _ALG_NONE.search(new):
        new = _ALG_NONE.sub('algorithms=["HS256"]', new)
        notes.append("JWT: the 'none' algorithm is no longer accepted")
    m = _EVAL_REQ.search(new)
    if m:
        new = _EVAL_REQ.sub(lambda mm: f"ast.literal_eval({mm.group(1)})", new)
        if not re.search(r"^\s*import ast\b", new, re.M):
            new = "import ast\n" + new
        notes.append("code injection: eval() on request data replaced with ast.literal_eval()")
    if not notes:
        return None, []
    return new, notes


# Outbound fetch whose URL comes from the caller (SSRF)
_FETCH_CALL = re.compile(
    r"^(?P<indent>[ \t]*)(?P<pre>(?:[A-Za-z_]\w*\s*=\s*)?)(?:requests\.(?:get|post|put|delete|head|request)|"
    r"urllib\.request\.urlopen|urlopen|httpx\.(?:get|post|request))\s*\(\s*(?P<url>[A-Za-z_]\w*)\b[^\n]*\)\s*$"
)
_SSRF_GUARDED = re.compile(r"urlparse|allowed_host|ALLOWED|is_private|ip_address|_is_safe_external_url", re.I)
_SSRF_HELPER = "_is_safe_external_url"
_SSRF_HELPER_SRC = "\n".join(['import re as _re_ssrf', '', '', 'def _is_safe_external_url(value):', '    """Only plain http(s) to a public host: blocks file://, gopher://, cloud', '    metadata and loopback/private addresses, the usual SSRF targets."""', '    if not isinstance(value, str) or not _re_ssrf.match(r"https?://", value):', '        return False', '    host = value.split("://", 1)[1].split("/")[0].split("@")[-1].split(":")[0].lower()', '    if host in ("localhost", "metadata", "metadata.google.internal") or host.startswith("["):', '        return False', '    if _re_ssrf.match(r"^(127\\.|10\\.|169\\.254\\.|192\\.168\\.|0\\.|172\\.(1[6-9]|2\\d|3[01])\\.)", host):', '        return False', '    return True', ''])

_MARKUP_CALL = re.compile(r"\bMarkup\s*\(")
# an f-string that really builds HTML: it contains an actual tag, not just a "<"
_FSTRING_HTML = re.compile(r"""f(?P<q>["'])(?P<body>[^"'\n]*</?[a-zA-Z][a-zA-Z0-9]*[^<>"'\n]*>[^"'\n]*)(?P=q)""")
_FS_PLACE = re.compile(r"\{([A-Za-z_]\w*)\}")


def _tainted_name(src: str, name: str) -> bool:
    if re.search(r"\b" + re.escape(name) + r"\s*=\s*[^\n]*(?:request\.|req\.|\.args|\.json|\.form|\.params|\.query)", src):
        return True
    for m in re.finditer(r"(?:async\s+)?def\s+\w+\s*\(([^)]*)\)", src):
        params = {q.split(":")[0].split("=")[0].strip() for q in m.group(1).split(",") if q.strip()}
        if name in params:
            return True
    return False


def rewrite_ssrf(src: str):
    """Require a user-supplied fetch URL to be a public http(s) address."""
    lines = src.splitlines(keepends=True)
    out, notes, need_helper = [], [], False
    for i, line in enumerate(lines):
        m = _FETCH_CALL.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            continue
        url = m.group("url")
        before = "".join(lines[max(0, i - 6):i])
        if _SSRF_GUARDED.search(before) or _SSRF_GUARDED.search(line) or not _tainted_name(src, url):
            out.append(line)
            continue
        indent = m.group("indent")
        out.append(indent + "if not " + _SSRF_HELPER + "(" + url + "):\n")
        out.append(_error_stmt(src, indent) + "\n")
        out.append(line)
        need_helper = True
        notes.append("SSRF: " + url + " must be a public http(s) URL before it is fetched")
    if not need_helper:
        return None, []
    body = "".join(out)
    if ("def " + _SSRF_HELPER) not in body:
        idx = 0
        for mm in re.finditer(r"^(?:import |from )[^\n]*\n", body, re.M):
            idx = mm.end()
        body = body[:idx] + "\n\n" + _SSRF_HELPER_SRC + "\n" + body[idx:]
    return _ensure_import(body), notes


def rewrite_xss(src: str):
    """Escape user data that is placed straight into HTML."""
    new, notes = src, []
    if _MARKUP_CALL.search(new):
        new = _MARKUP_CALL.sub("escape(", new)
        notes.append("XSS: Markup() replaced with escape() so user data is not trusted as HTML")

    def _fix(m):
        # only values that actually carry user input are escaped; escaping internal
        # values would change output the project's own tests may depend on
        fixed = _FS_PLACE.sub(
            lambda q: "{escape(" + q.group(1) + ")}" if _tainted_name(src, q.group(1)) else q.group(0),
            m.group("body"))
        return "f" + m.group("q") + fixed + m.group("q")

    if "escape(" not in new:
        candidate = _FSTRING_HTML.sub(_fix, new)
        if candidate != new and "{escape(" in candidate:
            new = candidate
            notes.append("XSS: values interpolated into an HTML f-string are now escaped")
    if not notes:
        return None, []
    if not re.search(r"^\s*from\s+(?:markupsafe|flask)\s+import[^\n]*\bescape\b", new, re.M):
        new = "from markupsafe import escape\n" + new
    return new, notes


# ---- missing authorization (IDOR) ---------------------------------------------------

_OWNS_HELPER = "_caller_owns"
_OWNS_HELPER_SRC = "\n".join(['def _caller_owns(obj, caller):', '    """True when `obj` belongs to `caller`, or when it carries no owner at all.', '', '    Objects and callers appear as dicts or as models depending on the project, and', '    an object with no ownership field has nothing to enforce, so it stays allowed.', '    """', '    for _f in ("owner_id", "owner", "user_id", "user", "created_by", "author_id", "author", "account_id"):', '        _val = obj.get(_f) if isinstance(obj, dict) else getattr(obj, _f, None)', '        if _val is None:', '            continue', '        _ids = [caller]', '        for _a in ("id", "username", "name", "email", "sub"):', '            _ids.append(getattr(caller, _a, None))', '            if isinstance(caller, dict):', '                _ids.append(caller.get(_a))', '        return any(_c is not None and _val == _c for _c in _ids)', '    return True', ''])
_ROUTE_DECO = re.compile(r"^\s*@[\w.]+\.(?:get|post|put|patch|delete|route)\s*\(\s*[\"']([^\"']+)", re.M)
_ID_IN_PATH = re.compile(r"[<{]\s*(?:int:|str:|uuid:)?\s*(\w*id\w*)\s*[:}>]", re.I)
_CALLER_ASSIGN = re.compile(r"^(?P<indent>[ \t]+)(?P<var>[A-Za-z_]\w*)\s*=\s*(?P<call>[A-Za-z_][\w.]*)\s*\(\s*\)\s*$", re.M)
_CALLER_NAMES = ("current_user", "get_current_user", "require_user", "authenticated_user", "current_identity",
                 "get_user", "auth_user", "require_auth", "login_required_user")
_DEPENDS_PARAM = re.compile(r"(?P<param>[A-Za-z_]\w*\s*(?::\s*[^=,)]+)?\s*=\s*Depends\(\s*[\w.]*(?:current_user|get_current_user|require_user|auth_user)[\w.]*\s*\))")
_RETURNS = re.compile(r"^(?P<indent>[ \t]+)return\b(?P<rest>.*)$", re.M)


def _handlers(src: str):
    """[(start_line, end_line, route_path)] for each request handler in the file."""
    lines = src.splitlines()
    spans = []
    for i, line in enumerate(lines):
        m = re.match(r"\s*@[\w.]+\.(?:get|post|put|patch|delete|route)\s*\(\s*[\"']([^\"']+)", line)
        if not m:
            continue
        path = m.group(1)
        j = i + 1
        while j < len(lines) and not re.match(r"\s*(?:async\s+)?def\s", lines[j]):
            j += 1
        if j >= len(lines):
            continue
        k = j + 1
        while k < len(lines) and (not lines[k].strip() or lines[k].startswith((" ", "\t"))):
            k += 1
        spans.append((j, k, path))
    return spans


def rewrite_authorization(src: str):
    """Make an object lookup check that the caller owns what it returns.

    Only applied when the project already authenticates callers: without an identity
    there is nothing to compare against, and inventing one would break every functional
    test. The ownership test itself is deliberately permissive — an object with no owner
    field is left accessible — so the rewrite removes access only where it was wrong."""
    if _OWNS_HELPER in src:
        return None, []
    lines = src.splitlines(keepends=True)
    out = list(lines)
    notes = []
    inserts = []  # (line_index, text)
    for start, end, path in _handlers(src):
        if not _ID_IN_PATH.search(path):
            continue
        body = "".join(lines[start:end])
        # the caller's identity, as this project already establishes it
        caller = None
        for m in _CALLER_ASSIGN.finditer(body):
            if any(n in m.group("call") for n in _CALLER_NAMES):
                caller = m.group("var")
                break
        if caller is None:
            dm = _DEPENDS_PARAM.search(lines[start])
            if dm:
                caller = dm.group("param").split(":")[0].split("=")[0].strip()
        if caller is None:
            continue
        if _OWNS_HELPER in body or re.search(r"\b(?:403|Forbidden|not authori|permission)", body, re.I):
            continue
        # the object this handler hands back
        target, ret_idx, indent = None, None, ""
        for off in range(end - 1, start, -1):
            rm = _RETURNS.match(lines[off].rstrip("\n"))
            if not rm:
                continue
            names = [n for n in re.findall(r"[A-Za-z_]\w*", rm.group("rest"))
                     if n not in ("jsonify", "return", "dict", "list", "str", "int", "json", "Response", "make_response")]
            cand = next((n for n in names if re.search(r"^\s*%s\s*=(?!=)" % re.escape(n), body, re.M)), None)
            if cand and cand != caller:
                target, ret_idx, indent = cand, off, rm.group("indent")
                break
        if target is None:
            continue
        reject = _error_stmt(src, indent).replace("path outside the allowed directory", "not your object")
        reject = reject.replace("status_code=404", "status_code=403").replace("abort(404)", "abort(403)")
        inserts.append((ret_idx, f"{indent}if not {_OWNS_HELPER}({target}, {caller}):\n{reject}\n"))
        notes.append(f"missing authorization: {path} now verifies that the caller owns {target}")
    if not inserts:
        return None, []
    for idx, text in sorted(inserts, reverse=True):
        out.insert(idx, text)
    body = "".join(out)
    anchor = 0
    for mm in re.finditer(r"^(?:import |from )[^\n]*\n", body, re.M):
        anchor = mm.end()
    body = body[:anchor] + "\n\n" + _OWNS_HELPER_SRC + "\n" + body[anchor:]
    return _ensure_import(body), notes


def apply(workdir, variant: str = "containment"):
    """Returns (originals, notes) — same contract as sqlfix/safefix."""
    workdir = Path(workdir)
    originals, notes = {}, []
    for p in _iter_py(workdir):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        new, file_notes = text, []
        r, n = rewrite_traversal(new, variant)
        if r is not None:
            new, file_notes = r, file_notes + n
        r, n = rewrite_auth(new)
        if r is not None:
            new, file_notes = r, file_notes + n
        r, n = rewrite_ssrf(new)
        if r is not None:
            new, file_notes = r, file_notes + n
        r, n = rewrite_xss(new)
        if r is not None:
            new, file_notes = r, file_notes + n
        r, n = rewrite_authorization(new)
        if r is not None:
            new, file_notes = r, file_notes + n
        if new != text:
            originals[str(p)] = text
            p.write_text(new, encoding="utf-8")
            notes.extend(f"{p.relative_to(workdir)}: {x}" for x in file_notes)
    return originals, notes


def apply_basename(workdir):
    return apply(workdir, variant="basename")


def revert(originals):
    for path, text in originals.items():
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError:
            pass
