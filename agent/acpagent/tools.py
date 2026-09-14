"""The agent's tool surface plus the tolerance layer a small model needs.

Only four tools are advertised (bash, read_file, write_file, str_replace): every extra
schema is resent on every request and a small model picks worse the more options it
has. Dispatch is forgiving about invented names and argument keys because answering
"unknown tool" throws away a whole round-trip.
"""

import difflib
import os
import py_compile
import re
import signal
import subprocess
import tempfile
from pathlib import Path

MAX_TOOL_OUTPUT_CHARS = 6500
DEFAULT_BASH_TIMEOUT = 120
MAX_BASH_TIMEOUT = 240
BINARY_SNIFF = 4096


def truncate(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Keep both ends of an oversized output: a pytest summary, the last lines of a
    log and the error a command died on all live at the tail."""
    if len(text) <= limit:
        return text
    head = int(limit * 0.55)
    tail = limit - head
    dropped = len(text) - limit
    return f"{text[:head]}\n... [{dropped} chars elided; narrow the command or use offset/limit] ...\n{text[-tail:]}"


def resolve(path, workdir: Path) -> Path:
    p = Path(str(path).strip().strip("'\"")).expanduser()
    return p if p.is_absolute() else (Path(workdir) / p)


def run_bash(command: str, workdir: Path, timeout: float = DEFAULT_BASH_TIMEOUT) -> str:
    """Run a shell command with output captured to a file (not a pipe), so a server
    the model backgrounds does not keep the call open until the timeout."""
    timeout = min(max(5.0, float(timeout or DEFAULT_BASH_TIMEOUT)), MAX_BASH_TIMEOUT)
    shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
    cwd = str(workdir) if Path(workdir).is_dir() else None
    try:
        with tempfile.TemporaryFile(mode="w+b") as out:
            proc = subprocess.Popen(
                command,
                shell=True,
                executable=shell,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            timed_out = False
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:  # noqa: BLE001
                    pass
            out.seek(0)
            data = out.read().decode("utf-8", "replace")
        if timed_out:
            data += (
                f"\n[error] command timed out after {int(timeout)}s and was killed. "
                "Long-running servers must be started with: nohup CMD > /tmp/server.log 2>&1 &"
            )
            code = 124
        else:
            code = proc.returncode
        body = data if data.strip() else "<no output>"
        if code != 0 and "syntax error" in data and ("python3 -c" in command or "python -c" in command):
            body += ("\n[hint] shell quoting broke the inline script. Write it as a heredoc instead:\n"
                     "python3 - <<'EOF'\n<script>\nEOF")
        elif code != 0 and ("syntax error" in data or "unexpected EOF" in data) and "<<" in command:
            body += "\n[hint] the heredoc terminator must be on its own line and match exactly (EOF)."
        return truncate(f"[exit {code}]\n{body}")
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    text_chars = bytes(range(32, 127)) + b"\n\r\t\b\f\x1b"
    nontext = data.translate(None, text_chars)
    return len(data) > 0 and len(nontext) / len(data) > 0.30


def read_file(path, workdir: Path, offset=None, limit=None) -> str:
    fp = resolve(path, workdir)
    if not fp.exists():
        return f"[error] File not found: {fp}{_suggest(fp)}"
    if fp.is_dir():
        return list_dir(fp)
    try:
        size = fp.stat().st_size
        with fp.open("rb") as fh:
            head = fh.read(BINARY_SNIFF)
        if _is_binary(head):
            return (f"[binary file: {fp}, {size} bytes] Inspect it with bash: "
                    f"file {fp}; strings -n 6 {fp} | head -100; od -An -tx1 -c {fp} | head -40")
        text = fp.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"
    lines = text.splitlines()
    total = len(lines)
    if offset is not None or limit is not None:
        try:
            start = max(1, int(offset or 1))
        except (TypeError, ValueError):
            start = 1
        try:
            count = max(1, int(limit or 200))
        except (TypeError, ValueError):
            count = 200
        chunk = lines[start - 1:start - 1 + count]
        body = "\n".join(chunk)
        note = f"[{fp}: lines {start}-{min(total, start - 1 + len(chunk))} of {total}]\n"
        return note + truncate(body, MAX_TOOL_OUTPUT_CHARS * 2)
    if len(text) <= MAX_TOOL_OUTPUT_CHARS:
        return text
    head_lines = []
    used = 0
    for ln in lines:
        if used + len(ln) + 1 > MAX_TOOL_OUTPUT_CHARS:
            break
        head_lines.append(ln)
        used += len(ln) + 1
    shown = len(head_lines)
    return ("\n".join(head_lines) +
            f"\n... [file continues: {total} lines total, showing 1-{shown}. "
            f"Use read_file with offset={shown + 1} and limit=200 to read more, or bash grep -n.]")


def _suggest(fp: Path) -> str:
    try:
        parent = fp.parent
        if parent.is_dir():
            names = sorted(p.name for p in list(parent.iterdir())[:60])
            if names:
                return f"\nEntries in {parent}: {', '.join(names)}"
        else:
            return f"\nDirectory {parent} does not exist."
    except OSError:
        pass
    return ""


def list_dir(fp: Path) -> str:
    rows = []
    try:
        for child in sorted(fp.iterdir()):
            try:
                size = child.stat().st_size
            except OSError:
                size = 0
            rows.append(f"{'d' if child.is_dir() else '-'} {size:>9} {child.name}")
    except OSError as exc:
        return f"[error] {exc}"
    return truncate(f"{fp}:\n" + "\n".join(rows[:300]))


def write_file(path, content, workdir: Path) -> str:
    fp = resolve(path, workdir)
    if content is None:
        content = ""
    if not isinstance(content, str):
        try:
            import json
            content = json.dumps(content, ensure_ascii=False, indent=2)
        except Exception:  # noqa: BLE001
            content = str(content)
    try:
        fp.parent.mkdir(parents=True, exist_ok=True)
        with fp.open("w", encoding="utf-8", newline="") as stream:
            stream.write(content)
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"
    msg = f"Wrote {len(content.encode('utf-8'))} bytes to {fp}"
    warn = post_write_check(fp)
    return msg + (f"\n{warn}" if warn else "")


def _normalise_ws(s: str) -> str:
    return "\n".join(line.rstrip() for line in s.replace("\r\n", "\n").split("\n"))


def str_replace(path, old, new, workdir: Path) -> str:
    fp = resolve(path, workdir)
    if not fp.is_file():
        return f"[error] File not found: {fp}{_suggest(fp)}"
    if old is None or old == "":
        return "[error] old_str must not be empty. Use write_file to create or overwrite a file."
    new = "" if new is None else str(new)
    old = str(old)
    try:
        body = fp.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"
    count = body.count(old)
    if count == 0:
        # Second chance: ignore trailing whitespace differences per line.
        nb, no = _normalise_ws(body), _normalise_ws(old)
        if no and nb.count(no) == 1:
            idx = nb.find(no)
            # map back by rebuilding the file from the normalised version: safe because
            # only trailing whitespace was removed.
            body2 = nb[:idx] + _normalise_ws(new) + nb[idx + len(no):]
            try:
                with fp.open("w", encoding="utf-8", newline="") as stream:
                    stream.write(body2)
            except Exception as exc:  # noqa: BLE001
                return f"[error] {exc}"
            warn = post_write_check(fp)
            return f"Replaced 1 occurrence in {fp} (matched ignoring trailing whitespace)." + (f"\n{warn}" if warn else "")
        hint = _closest_snippet(body, old)
        return (f"[error] old_str not found in {fp}. It must match the file text exactly "
                f"(same indentation and line breaks). Closest text in the file:\n{hint}")
    if count > 1:
        return f"[error] old_str occurs {count} times in {fp}; include more surrounding lines so it is unique."
    try:
        with fp.open("w", encoding="utf-8", newline="") as stream:
            stream.write(body.replace(old, new, 1))
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"
    warn = post_write_check(fp)
    return f"Replaced 1 occurrence in {fp}." + (f"\n{warn}" if warn else "")


def _closest_snippet(body: str, needle: str) -> str:
    lines = body.splitlines()
    first = next((ln for ln in needle.splitlines() if ln.strip()), needle.strip())
    best = difflib.get_close_matches(first.strip(), [ln.strip() for ln in lines], n=1, cutoff=0.5)
    if not best:
        return "(no similar line found)"
    for i, ln in enumerate(lines):
        if ln.strip() == best[0]:
            lo, hi = max(0, i - 2), min(len(lines), i + 4)
            return "\n".join(f"{j + 1}: {lines[j]}" for j in range(lo, hi))
    return best[0]


def post_write_check(fp: Path):
    """Cheap validation after an edit so a broken file is reported in the same round."""
    suffix = fp.suffix.lower()
    try:
        if suffix == ".py":
            py_compile.compile(str(fp), doraise=True, cfile=os.devnull)
        elif suffix == ".json":
            import json
            json.loads(fp.read_text(encoding="utf-8", errors="replace"))
        elif suffix == ".php":
            if _which("php"):
                p = subprocess.run(["php", "-l", str(fp)], capture_output=True, text=True, timeout=20)
                if p.returncode != 0:
                    return "[warning] php -l reports a syntax error:\n" + truncate(p.stdout + p.stderr, 800)
        elif suffix in (".js", ".mjs", ".cjs"):
            if _which("node"):
                p = subprocess.run(["node", "--check", str(fp)], capture_output=True, text=True, timeout=20)
                if p.returncode != 0:
                    return "[warning] node --check reports a syntax error:\n" + truncate(p.stderr, 800)
    except py_compile.PyCompileError as exc:
        return f"[warning] the file now has a Python syntax error - fix it before finishing:\n{truncate(str(exc), 800)}"
    except ValueError as exc:
        return f"[warning] the file is not valid JSON: {exc}"
    except Exception:  # noqa: BLE001
        return None
    return None


def _which(name: str):
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and os.path.exists(os.path.join(d, name)):
            return os.path.join(d, name)
    return None


# ---- schemas & dispatch --------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "bash",
            "description": (
                "Run a shell command in the working directory and return its output "
                "(stdout+stderr, exit code). Use for exploring (ls, grep -rn, file, strings), "
                "running scripts (python3 -c '...'), and running tests."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to run."},
                    "timeout": {"type": "integer", "description": "Seconds before the command is killed (default 120)."},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a text file (absolute path or relative to the working directory). Large files are paged: pass offset (1-based line) and limit.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "offset": {"type": "integer", "description": "First line to show (1-based)."},
                    "limit": {"type": "integer", "description": "Number of lines to show."},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Create or overwrite a file with the given content, exactly as provided "
                "(no trailing newline is added). Creates parent directories."
            ),
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "str_replace",
            "description": (
                "Edit a file by replacing one exact, unique snippet (old_str) with new_str. "
                "Preferred for source-code edits. old_str must match the file text exactly and occur once."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "old_str": {"type": "string"},
                    "new_str": {"type": "string"},
                },
                "required": ["path", "old_str", "new_str"],
            },
        },
    },
]

TOOL_NAMES = {t["function"]["name"] for t in TOOL_SCHEMAS} | {"list_dir", "grep", "apply_patch"}

_ALIASES = {
    "shell": "bash", "run": "bash", "run_bash": "bash", "run_command": "bash", "execute": "bash",
    "execute_bash": "bash", "execute_command": "bash", "terminal": "bash", "command": "bash",
    "sh": "bash", "python": "bash", "run_shell": "bash", "exec": "bash", "cmd": "bash",
    "run_terminal_cmd": "bash", "shell_command": "bash", "bash_tool": "bash", "run_python": "bash",
    "cat": "read_file", "open_file": "read_file", "view": "read_file", "view_file": "read_file",
    "readfile": "read_file", "get_file": "read_file", "read": "read_file", "open": "read_file",
    "read_text_file": "read_file", "show_file": "read_file", "file_read": "read_file",
    "ls": "list_dir", "list_files": "list_dir", "list_directory": "list_dir", "listdir": "list_dir",
    "tree": "list_dir", "list_dir": "list_dir", "dir": "list_dir",
    "create_file": "write_file", "writefile": "write_file", "save_file": "write_file",
    "put_file": "write_file", "write": "write_file", "write_to_file": "write_file",
    "file_write": "write_file", "create": "write_file", "save": "write_file", "append_file": "write_file",
    "edit_file": "str_replace", "replace": "str_replace", "replace_in_file": "str_replace",
    "edit": "str_replace", "str_replace_editor": "str_replace", "search_replace": "str_replace",
    "patch_file": "str_replace", "modify_file": "str_replace",
    "search": "grep", "rg": "grep", "find": "grep", "grep": "grep", "search_files": "grep",
    "apply_diff": "apply_patch", "patch": "apply_patch", "apply_patch": "apply_patch",
}

_ARG_ALIASES = {
    "command": ("command", "cmd", "shell_command", "script", "code", "input", "commands", "bash", "shell", "query"),
    "path": ("path", "file_path", "filename", "file", "filepath", "target", "file_name", "target_file", "filePath", "name"),
    "content": ("content", "contents", "text", "data", "body", "new_content", "file_text", "code", "value"),
    "old_str": ("old_str", "old", "old_string", "search", "find", "from", "original", "old_text", "target", "before"),
    "new_str": ("new_str", "new", "new_string", "replace", "replacement", "to", "new_text", "after"),
    "diff": ("diff", "patch", "diff_content", "unified_diff"),
    "pattern": ("pattern", "query", "regex", "needle", "search", "text"),
    "offset": ("offset", "start", "start_line", "from_line", "line"),
    "limit": ("limit", "count", "lines", "num_lines", "n"),
    "timeout": ("timeout", "timeout_sec", "seconds"),
}


def _arg(args: dict, key: str, default=None):
    for name in _ARG_ALIASES.get(key, (key,)):
        if name in args and args[name] is not None:
            return args[name]
    return default


def canonical_name(name) -> str:
    n = (str(name) or "").strip().lower()
    n = n.split(".")[-1]
    n = n.replace("-", "_")
    if n.startswith("functions_"):
        n = n[len("functions_"):]
    return _ALIASES.get(n, n)


def apply_patch(path, diff, workdir: Path) -> str:
    fp = resolve(path, workdir)
    if not fp.is_file():
        return f"[error] File not found: {fp}"
    try:
        p = subprocess.run(["patch", "-N", "-r", "-", str(fp)], input=diff, capture_output=True,
                           text=True, timeout=20)
        status = "Applied" if p.returncode == 0 else "Failed to apply"
        return truncate(f"{status} diff to {fp}\n[exit {p.returncode}]\n{p.stdout}\n{p.stderr}")
    except Exception as exc:  # noqa: BLE001
        return f"[error] {exc}"


def grep(pattern, path, workdir: Path) -> str:
    import shlex
    q = shlex.quote(str(pattern))
    t = shlex.quote(str(resolve(path or ".", workdir)))
    return run_bash(f"rg -n --no-heading -S -- {q} {t} 2>/dev/null || grep -rn -- {q} {t}", workdir, 60)


def dispatch(name, args, workdir: Path) -> str:
    if not isinstance(args, dict):
        args = {"_raw": args}
    tool = canonical_name(name)
    try:
        if tool == "bash":
            command = _arg(args, "command")
            if not command and "_raw" in args:
                command = args["_raw"]
            if not command:
                return "[error] bash needs a 'command' string"
            if isinstance(command, list):
                command = " && ".join(str(c) for c in command)
            return run_bash(str(command), workdir, _arg(args, "timeout", DEFAULT_BASH_TIMEOUT))
        if tool == "read_file":
            path = _arg(args, "path") or args.get("_raw")
            if not path:
                return "[error] read_file needs a 'path'"
            return read_file(str(path), workdir, _arg(args, "offset"), _arg(args, "limit"))
        if tool == "list_dir":
            return list_dir(resolve(str(_arg(args, "path", ".") or "."), workdir))
        if tool == "write_file":
            path = _arg(args, "path")
            if not path:
                return "[error] write_file needs a 'path'"
            return write_file(str(path), _arg(args, "content", ""), workdir)
        if tool == "str_replace":
            path = _arg(args, "path")
            if not path:
                return "[error] str_replace needs a 'path'"
            return str_replace(str(path), _arg(args, "old_str", ""), _arg(args, "new_str", ""), workdir)
        if tool == "apply_patch":
            return apply_patch(str(_arg(args, "path", "")), str(_arg(args, "diff", "") or ""), workdir)
        if tool == "grep":
            pattern = _arg(args, "pattern")
            if not pattern:
                return "[error] grep needs a 'pattern'"
            return grep(str(pattern), str(_arg(args, "path", ".") or "."), workdir)
    except Exception as exc:  # noqa: BLE001
        return f"[error] {tool} failed: {exc}"
    return f"[error] unknown tool {name!r}. Available tools: bash, read_file, write_file, str_replace."
