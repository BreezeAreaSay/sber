"""Mechanical, test-verified rewrites for defects other than SQL injection.

Each rewrite is a local, semantics-preserving transformation a reviewer would make
without thinking; they are kept only when the project still passes its tests.
"""

import re
from pathlib import Path

_SHELL_META = re.compile(r"[|&;<>`$*?\[\]\\!(){}'\"~]")
_SUBPROC_CALL = re.compile(
    r"(?P<head>\bsubprocess\.(?P<fn>run|call|check_call|check_output|Popen)\(\s*)"
    r"(?P<str>f(?P<q>['\"])(?P<tpl>[^\n]*?)(?P=q))"
    r"(?P<rest>\s*,[^\n]*?)?\)"
)
_OS_SYSTEM = re.compile(r"\bos\.system\(\s*f(?P<q>['\"])(?P<tpl>[^\n]*?)(?P=q)\s*\)")
_PLACE = re.compile(r"\{([^{}:!]+)\}")


def _argv_from_template(tpl: str):
    """Split an f-string command template into argv tokens; None if unsafe."""
    tpl = tpl.strip()
    trailing_true = False
    if tpl.endswith("|| true"):
        trailing_true = True
        tpl = tpl[:-len("|| true")].rstrip()
    if _SHELL_META.search(_PLACE.sub("X", tpl)):
        return None
    tokens = tpl.split()
    argv = []
    for tok in tokens:
        m = _PLACE.fullmatch(tok)
        if m:
            expr = m.group(1).strip()
            if not expr or "join(" in expr:
                return None
            argv.append(expr)
        elif "{" in tok or "}" in tok:
            return None  # placeholder glued to other characters: cannot split safely
        else:
            argv.append(repr(tok))
    if not argv or argv[0].startswith(("'", '"')) is False:
        return None  # the program name must be a literal
    return argv, trailing_true


def _strip_shell_kw(rest: str) -> str:
    rest = re.sub(r",\s*shell\s*=\s*True", "", rest or "")
    return rest


def rewrite_commands(src: str):
    notes = []
    out = src
    # subprocess.X(f"...", shell=True, ...)
    def repl(m):
        rest = m.group("rest") or ""
        if "shell=True" not in rest.replace(" ", ""):
            return m.group(0)
        parsed = _argv_from_template(m.group("tpl"))
        if parsed is None:
            return m.group(0)
        argv, trailing_true = parsed
        rest2 = _strip_shell_kw(rest)
        fn = m.group("fn")
        lst = "[" + ", ".join(argv) + "]"
        if fn == "check_output" and trailing_true:
            # `cmd || true` swallowed failures; run() without check does the same
            kw = rest2.lstrip(",").strip()
            kw = (", " + kw) if kw else ""
            call = f"subprocess.run({lst}{kw}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout"
            if "text=True" not in kw and "universal_newlines" not in kw:
                call = call.replace(").stdout", ", text=True).stdout")
            notes.append(f"subprocess.check_output(f\"...\", shell=True) -> subprocess.run([...]) (no shell)")
            return call
        notes.append(f"subprocess.{fn}(f\"...\", shell=True) -> argument list (no shell)")
        return f"{m.group('head')}{lst}{rest2})"
    out = _SUBPROC_CALL.sub(repl, out)
    # os.system(f"...")
    def repl2(m):
        parsed = _argv_from_template(m.group("tpl"))
        if parsed is None:
            return m.group(0)
        argv, _ = parsed
        notes.append("os.system(f\"...\") -> subprocess.call([...])")
        return f"subprocess.call([{', '.join(argv)}])"
    out2 = _OS_SYSTEM.sub(repl2, out)
    if out2 != out and not re.search(r"^\s*(?:import\s+[^\n]*\bsubprocess\b|from\s+subprocess\s+import)", out2, re.M):
        out2 = "import subprocess\n" + out2
    out = out2
    return (out if notes else None), notes


_SAFE_ONE_LINERS = [
    (re.compile(r"\byaml\.load\(\s*([^,()]+?)\s*\)"), r"yaml.safe_load(\1)", "yaml.load -> yaml.safe_load"),
    (re.compile(r"\byaml\.load\(\s*([^,()]+?)\s*,\s*Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader|FullLoader)\s*\)"), r"yaml.safe_load(\1)", "yaml.load(Loader=...) -> yaml.safe_load"),
    (re.compile(r"(\bapp\.run\([^)\n]*?)debug\s*=\s*True"), r"\1debug=False", "app.run(debug=True) -> debug=False"),
    (re.compile(r"(\brequests\.\w+\([^)\n]*?)verify\s*=\s*False"), r"\1verify=True", "requests verify=False -> verify=True"),
    (re.compile(r"\btempfile\.mktemp\("), "tempfile.mkstemp(", "tempfile.mktemp -> mkstemp"),
]


def rewrite_safe(src: str):
    notes = []
    out = src
    for rx, rep, note in _SAFE_ONE_LINERS:
        new, n = rx.subn(rep, out)
        if n:
            out = new
            notes.append(f"{note} (x{n})")
    if "tempfile.mkstemp(" in out and "mktemp" in "".join(notes):
        # mkstemp returns (fd, path); a plain rename would change semantics — undo it
        out = src
        notes = [n for n in notes if "mktemp" not in n]
        if not notes:
            return None, []
    return (out if notes else None), notes


def apply(workdir):
    """Returns (originals, notes)."""
    workdir = Path(workdir)
    originals, notes = {}, []
    skip = {".venv", "venv", "site-packages", "node_modules", "build", "dist", ".git", "__pycache__", ".eggs"}
    for p in workdir.rglob("*.py"):
        if set(p.parts) & skip or p.name.startswith("test"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        new = text
        file_notes = []
        r, n = rewrite_commands(new)
        if r is not None:
            new, file_notes = r, file_notes + n
        r, n = rewrite_safe(new)
        if r is not None:
            new, file_notes = r, file_notes + n
        if new != text:
            originals[str(p)] = text
            p.write_text(new, encoding="utf-8")
            notes.extend(f"{p.relative_to(workdir)}: {x}" for x in file_notes)
    return originals, notes


def revert(originals):
    for path, text in originals.items():
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError:
            pass
