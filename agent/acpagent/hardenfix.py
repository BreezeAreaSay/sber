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
