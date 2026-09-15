"""Mechanical security fixes for JavaScript and TypeScript services.

The runtime image ships no Node, so an application written in JavaScript would have to
bring its own — and a rewrite here cannot be checked by `py_compile` the way the Python
fixers are. These rewrites are therefore applied only when the project's own test suite
actually runs and passes afterwards (`require_tests` in the verification stage); if the
tests cannot run at all, the change is reverted rather than kept on trust.

Covered: SQL built by concatenation or template literal, `child_process` with a shell
string, and a filesystem path joined from user input.
"""

import re
from pathlib import Path

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "coverage", ".next", "out", "__pycache__"}
_EXTS = (".js", ".mjs", ".cjs", ".ts")

# db.query("SELECT ... " + x)  /  db.query(`SELECT ... ${x}`)
_QUERY_CALL = re.compile(
    r"(?P<pre>\b(?:query|execute|all|get|run)\s*\(\s*)(?P<arg>(?:`[^`]*`|\"[^\"]*\"|'[^']*')(?:\s*\+\s*[^,;)]+)*)",
)
_TEMPLATE_VAR = re.compile(r"\$\{\s*([A-Za-z_$][\w.$\[\]']*)\s*\}")
_SQL_WORD = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|SET)\b", re.I)

# child_process.exec("cmd " + x) / execSync(`cmd ${x}`)
_EXEC_CALL = re.compile(
    r"\b(?P<fn>exec|execSync)\s*\(\s*(?P<arg>(?:`[^`]*`|\"[^\"]*\"|'[^']*')(?:\s*\+\s*[^,;)]+)*)\s*(?P<rest>[,)])"
)

_PATH_JOIN = re.compile(
    r"^(?P<indent>[ \t]*)(?:const|let|var)?\s*(?P<var>[A-Za-z_$][\w$]*)\s*=\s*path\.join\(\s*(?P<base>[A-Za-z_$][\w$.]*)\s*,\s*(?P<rest>[^\n;]*?)\)\s*;?\s*$",
    re.M,
)
_USERISH = re.compile(r"req\.|request\.|params|query|body|filename|fileName|\bname\b|\bfile\b", re.I)
_PATH_GUARDED = re.compile(r"path\.resolve|startsWith|normalize|basename", re.I)


def _iter_js(workdir: Path):
    for p in Path(workdir).rglob("*"):
        if p.suffix.lower() not in _EXTS or not p.is_file():
            continue
        if set(p.parts) & _SKIP_DIRS or ".test." in p.name or ".spec." in p.name:
            continue
        yield p


_QUOTED_MARKER = re.compile(r"'(\?|\$\d+)'")


def _strip_quoted_markers(sql: str) -> str:
    """A parameter marker must not sit inside SQL quotes.

    `name = '" + x + "'` becomes `name = ?`, not `name = '?'` — the latter compares
    against a literal question mark and silently matches nothing."""
    return _QUOTED_MARKER.sub(r"\1", sql)


def _placeholder(src: str, index: int) -> str:
    """The parameter marker this driver uses: postgres counts, everyone else uses ?."""
    return f"${index}" if re.search(r"\bpg\b|postgres|Pool\s*\(", src) else "?"


def rewrite_sql(src: str):
    """Turn a concatenated or interpolated SQL string into a parameterized query."""
    notes = []

    def fix(m):
        arg = m.group("arg")
        if not _SQL_WORD.search(arg):
            return m.group(0)
        params = []
        if arg.startswith("`"):
            body = arg[1:-1]
            if not _TEMPLATE_VAR.search(body):
                return m.group(0)

            def sub(v):
                params.append(v.group(1))
                return _placeholder(src, len(params))

            body = _strip_quoted_markers(_TEMPLATE_VAR.sub(sub, body))
            new_arg = "`" + body + "`"
        else:
            parts = re.split(r"\s*\+\s*", arg)
            rebuilt = []
            for part in parts:
                part = part.strip()
                if part[:1] in "\"'`":
                    rebuilt.append(part[1:-1])
                else:
                    params.append(part)
                    rebuilt.append(_placeholder(src, len(params)))
            if not params:
                return m.group(0)
            new_arg = '"' + _strip_quoted_markers("".join(rebuilt)).replace('"', '\\"') + '"'
        notes.append(f"SQL injection: parameterized {len(params)} value(s): {', '.join(params)}")
        return m.group("pre") + new_arg + ", [" + ", ".join(params) + "]"

    new = _QUERY_CALL.sub(fix, src)
    return (new, notes) if notes else (None, [])


def rewrite_exec(src: str):
    """Replace a shell command built from input with an argument vector."""
    notes = []

    def fix(m):
        arg = m.group("arg")
        argv = []
        if arg.startswith("`"):
            body = arg[1:-1]
            if not _TEMPLATE_VAR.search(body):
                return m.group(0)
            pieces = _TEMPLATE_VAR.split(body)
            literal_words = pieces[0].split()
            if not literal_words:
                return m.group(0)
            cmd = literal_words[0]
            for i, piece in enumerate(pieces):
                if i % 2 == 1:
                    argv.append(piece)
                else:
                    argv.extend(f'"{w}"' for w in piece.split()[(1 if i == 0 else 0):])
        else:
            parts = re.split(r"\s*\+\s*", arg)
            head = parts[0].strip()
            if head[:1] not in "\"'":
                return m.group(0)
            words = head[1:-1].split()
            if not words:
                return m.group(0)
            cmd = words[0]
            argv = [f'"{w}"' for w in words[1:]] + [q.strip() for q in parts[1:] if q.strip()]
        if not argv:
            return m.group(0)
        notes.append(f"command injection: {m.group('fn')} replaced with execFile and an argument list")
        return f'execFile("{cmd}", [{", ".join(argv)}]' + m.group("rest")

    new = _EXEC_CALL.sub(fix, src)
    if notes and "execFile" not in src.split("execFile(")[0][:400]:
        if re.search(r"require\(['\"]child_process['\"]\)", new):
            new = re.sub(r"(const|let|var)\s*\{([^}]*)\}\s*=\s*require\(['\"]child_process['\"]\)",
                         lambda mm: f"{mm.group(1)} {{{mm.group(2).rstrip()}, execFile}} = require('child_process')",
                         new, count=1)
        else:
            new = "const { execFile } = require('child_process');\n" + new
    return (new, notes) if notes else (None, [])


def rewrite_path(src: str):
    """Keep a path built from user input inside its base directory."""
    notes = []
    lines = src.splitlines(keepends=True)
    out = []
    for i, line in enumerate(lines):
        out.append(line)
        m = _PATH_JOIN.match(line.rstrip("\n"))
        if not m or not _USERISH.search(m.group("rest")):
            continue
        if _PATH_GUARDED.search("".join(lines[i + 1:i + 5])):
            continue
        indent, var, base = m.group("indent"), m.group("var"), m.group("base")
        out.append(f'{indent}if (!path.resolve({var}).startsWith(path.resolve({base}) + require("path").sep)) '
                   f'{{ throw new Error("path outside the allowed directory"); }}\n')
        notes.append(f"path traversal: {var} is now required to stay inside {base}")
    return ("".join(out), notes) if notes else (None, [])


def apply(workdir):
    """Returns (originals, notes) — same contract as sqlfix/safefix/hardenfix."""
    workdir = Path(workdir)
    originals, notes = {}, []
    for p in _iter_js(workdir):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        new, file_notes = text, []
        for fn in (rewrite_sql, rewrite_exec, rewrite_path):
            r, n = fn(new)
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


# ---- checking a rewrite without a JavaScript runtime -------------------------------------

_KEYWORD_BEFORE_REGEX = ("return", "typeof", "instanceof", "in", "of", "new", "delete", "void",
                         "throw", "case", "do", "else", "yield", "await")


def syntax_errors(text: str):
    """Structural problems in a JavaScript source, found without running JavaScript.

    The image ships no Node, so a rewrite here would otherwise go out unchecked. This is
    not a parser: it tracks strings, template literals, regular expressions and comments,
    and reports a source whose delimiters do not balance or whose quotes do not close —
    which is what a botched rewrite actually looks like."""
    stack, i, n, line = [], 0, len(text), 1
    pairs = {")": "(", "]": "[", "}": "{"}
    prev_significant = ""
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            i = text.find("\n", i)
            if i == -1:
                break
            continue
        if c == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            if end == -1:
                return [f"unterminated block comment opened on line {line}"]
            line += text.count("\n", i, end)
            i = end + 2
            continue
        if c in "\"'":
            j, start_line = i + 1, line
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "\n":
                    return [f"unterminated {c} string on line {start_line}"]
                if text[j] == c:
                    break
                j += 1
            if j >= n:
                return [f"unterminated {c} string on line {start_line}"]
            i = j + 1
            prev_significant = "str"
            continue
        if c == "`":
            j, start_line, depth = i + 1, line, 0
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                elif text[j] == "$" and j + 1 < n and text[j + 1] == "{":
                    depth += 1
                    j += 1
                elif text[j] == "}" and depth:
                    depth -= 1
                elif text[j] == "`" and not depth:
                    break
                j += 1
            if j >= n:
                return [f"unterminated template literal on line {start_line}"]
            i = j + 1
            prev_significant = "str"
            continue
        if c == "/" and (prev_significant in ("", "op") or prev_significant in _KEYWORD_BEFORE_REGEX):
            j, start_line, klass = i + 1, line, False
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "\n":
                    break
                if text[j] == "[":
                    klass = True
                elif text[j] == "]":
                    klass = False
                elif text[j] == "/" and not klass:
                    break
                j += 1
            if j < n and text[j] == "/":
                i = j + 1
                prev_significant = "str"
                continue
            del start_line
        if c in "([{":
            stack.append((c, line))
        elif c in ")]}":
            if not stack:
                return [f"stray {c!r} on line {line}"]
            opener, opened = stack.pop()
            if opener != pairs[c]:
                return [f"{c!r} on line {line} does not close the {opener!r} opened on line {opened}"]
        if not c.isspace():
            prev_significant = "op" if c in "=(,;:[{&|!?+-*%<>~^" else "val"
        i += 1
    if stack:
        opener, opened = stack[-1]
        return [f"{opener!r} opened on line {opened} is never closed"]
    return []


def check_files(paths):
    """[] when every file is structurally sound; messages otherwise. Uses node when the
    task image happens to provide one, and the structural scan when it does not."""
    import shutil
    import subprocess
    node = shutil.which("node")
    out = []
    for p in paths:
        p = Path(p)
        if p.suffix.lower() not in _EXTS:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if node and p.suffix.lower() in (".js", ".cjs", ".mjs"):
            try:
                r = subprocess.run([node, "--check", str(p)], capture_output=True, text=True, timeout=20)
                if r.returncode != 0:
                    out.append(f"{p}: {(r.stderr or r.stdout).strip()[-400:]}")
                continue
            except Exception:  # noqa: BLE001
                pass
        out.extend(f"{p}: {e}" for e in syntax_errors(text))
    return out
