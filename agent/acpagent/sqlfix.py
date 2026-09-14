"""Mechanical rewrite of SQL built with Python f-strings into parameterized queries.

Rewriting `f"... WHERE name = '{x}'"` into `"... WHERE name = $1"` plus a bound
argument is a transformation, not a judgement call, and it is exactly what a small
model gets wrong (it adds the placeholder and forgets the argument). The rewrite is
only kept if the project's tests still pass; anything it cannot handle safely
(identifiers, IN-lists, joins built from input) is left for the model.
"""

import re
from pathlib import Path

_SQL_KW = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|LIKE|ORDER BY|SET)\b")
# `'{expr}'`, `'%{expr}%'`, `{expr}` inside an f-string (no nested braces / format specs)
_PLACEHOLDER = re.compile(r"'(%?)\{([^{}:!]+?)\}(%?)'|\"(%?)\{([^{}:!]+?)\}(%?)\"|(?<![{'\"%])\{([^{}:!]+?)\}(?![}'\"%])")
_CALL_RE = re.compile(r"\b(?:await\s+)?([\w.]+)\.(fetch|fetchrow|fetchval|fetchall|fetchone|execute|executemany|query)\(\s*")


class Driver:
    def __init__(self, style, tuple_args):
        self.style = style          # "$n" | "%s" | "?"
        self.tuple_args = tuple_args

    def placeholder(self, n):
        return f"${n}" if self.style == "$n" else self.style


def detect_driver(text: str, tree_text: str = ""):
    blob = text + "\n" + tree_text
    if "asyncpg" in blob:
        return Driver("$n", False)
    if re.search(r"\bpsycopg", blob) or "mysql" in blob.lower() or "pymysql" in blob:
        return Driver("%s", True)
    if "sqlite3" in blob or "aiosqlite" in blob:
        return Driver("?", True)
    return None


def _fstring_spans(src: str):
    """Yield (start, end, quote, inner) for every f-string literal (non-triple)."""
    i = 0
    n = len(src)
    while i < n:
        m = re.compile(r"(?<![\w])[fF][rR]?(['\"])").search(src, i)
        if not m:
            return
        q = m.group(1)
        j = m.end()
        if src.startswith(q * 3, m.start(1)):
            i = m.end() + 2
            continue
        buf = []
        while j < n:
            c = src[j]
            if c == "\\":
                buf.append(src[j:j + 2])
                j += 2
                continue
            if c == q:
                break
            if c == "\n":
                break
            buf.append(c)
            j += 1
        if j < n and src[j] == q:
            yield m.start(), j + 1, q, "".join(buf)
        i = j + 1


def _rewrite_fstring(inner: str, driver: Driver, counter: list, params: list):
    """Return the plain-string body with placeholders, or None if unsafe."""
    out = []
    pos = 0
    for m in _PLACEHOLDER.finditer(inner):
        if m.group(2) is not None:
            pre, expr, post = m.group(1), m.group(2), m.group(3)
        elif m.group(5) is not None:
            pre, expr, post = m.group(4), m.group(5), m.group(6)
        else:
            pre, expr, post = "", m.group(7), ""
        expr = expr.strip()
        if not expr or "join(" in expr or expr.startswith("'") or expr.startswith('"'):
            return None
        # bare {expr} used as an identifier (table/column) or after ORDER BY is not parameterizable
        before = inner[:m.start()].rstrip().upper()
        if m.group(2) is None and m.group(5) is None:
            if before.endswith(("FROM", "INTO", "UPDATE", "JOIN", "ORDER BY", "BY", "TABLE", "SET", "ASC", "DESC", ",")) or before.endswith("SELECT"):
                return None
            if re.search(r"(?:=|LIKE|IN|>|<|,|\()\s*$", before) is None:
                return None
        counter[0] += 1
        if pre or post:
            params.append(f'f"{pre}{{{expr}}}{post}"')
        else:
            params.append(expr)
        out.append(inner[pos:m.start()])
        out.append(driver.placeholder(counter[0]))
        pos = m.end()
    out.append(inner[pos:])
    body = "".join(out)
    if "{" in body.replace("{{", "").replace("}}", ""):
        return None
    return body.replace("{{", "{").replace("}}", "}")


def _statement_end(src: str, start: int) -> int:
    """End index of the statement that starts at `start` (balanced parens, newline)."""
    depth = 0
    i = start
    n = len(src)
    in_q = None
    while i < n:
        c = src[i]
        if in_q:
            if c == "\\":
                i += 2
                continue
            if c == in_q:
                in_q = None
        elif c in "\"'":
            in_q = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "\n" and depth <= 0:
            return i
        i += 1
    return n


def rewrite_source(src: str, driver: Driver):
    """Rewrite one file. Returns (new_src, notes) — new_src is None if nothing changed."""
    notes = []
    changed = False
    # 1. assignments:  name = f"..."  |  name = (f"..." f"...")
    assign_re = re.compile(r"^(?P<indent>[ \t]*)(?P<var>\w+)\s*=\s*(?P<open>\(?)\s*(?=[fF][rR]?['\"])", re.M)
    pos = 0
    out = src
    while True:
        m = assign_re.search(out, pos)
        if not m:
            break
        stmt_end = _statement_end(out, m.start())
        stmt = out[m.start():stmt_end]
        spans = list(_fstring_spans(stmt))
        if not spans or not any(_SQL_KW.search(s[3]) for s in spans):
            pos = stmt_end + 1
            continue
        # everything in the statement after '=' must be f-strings, whitespace, parens
        rest = stmt[m.end() - m.start():]
        skeleton = rest
        for s, e, q, inner in reversed(spans):
            s2 = s - (m.end() - m.start())
            e2 = e - (m.end() - m.start())
            skeleton = skeleton[:s2] + skeleton[e2:]
        if re.sub(r"[\s()]", "", skeleton) != "":
            pos = stmt_end + 1
            continue
        counter = [0]
        params = []
        bodies = []
        ok = True
        for s, e, q, inner in spans:
            body = _rewrite_fstring(inner, driver, counter, params)
            if body is None:
                ok = False
                break
            bodies.append(body)
        if not ok or not params:
            pos = stmt_end + 1
            continue
        var = m.group("var")
        # 2. find the call that consumes `var` after this statement in the same function
        tail = out[stmt_end:]
        call = re.search(r"\b(?:await\s+)?[\w.]+\.(?:fetch|fetchrow|fetchval|fetchall|fetchone|execute|executemany|query)\(\s*" + re.escape(var) + r"\s*(\)|,)", tail)
        if not call:
            pos = stmt_end + 1
            continue
        if call.group(1) == ",":
            pos = stmt_end + 1  # already has arguments; too risky
            continue
        joined = '"' + "".join(bodies).replace('"', '\\"') + '"'
        new_stmt = f"{m.group('indent')}{var} = {joined}"
        args = ", ".join(params)
        arg_text = f"({args},)" if driver.tuple_args else args
        call_start = stmt_end + call.start()
        call_end = stmt_end + call.end()
        call_text = out[call_start:call_end]
        new_call = call_text[:-1] + ", " + arg_text + ")"
        out = out[:m.start()] + new_stmt + out[stmt_end:call_start] + new_call + out[call_end:]
        notes.append(f"{var}: parameterized {len(params)} value(s): {args}")
        changed = True
        pos = m.start() + len(new_stmt) + 1
    # 3. inline:  conn.execute(f"... {x} ...")
    inline_re = re.compile(r"(\b(?:await\s+)?[\w.]+\.(?:fetch|fetchrow|fetchval|fetchall|fetchone|execute|query)\(\s*)(?=[fF][rR]?['\"])")
    pos = 0
    while True:
        m = inline_re.search(out, pos)
        if not m:
            break
        spans = list(_fstring_spans(out[m.end():m.end() + 2000]))
        if not spans or spans[0][0] != 0:
            pos = m.end()
            continue
        s, e, q, inner = spans[0]
        if not _SQL_KW.search(inner):
            pos = m.end()
            continue
        after = out[m.end() + e:m.end() + e + 3]
        if not after.lstrip().startswith(")"):
            pos = m.end()
            continue
        counter, params = [0], []
        body = _rewrite_fstring(inner, driver, counter, params)
        if body is None or not params:
            pos = m.end()
            continue
        args = ", ".join(params)
        arg_text = f"({args},)" if driver.tuple_args else args
        lit = '"' + body.replace('"', '\\"') + '"'
        out = out[:m.end()] + lit + ", " + arg_text + out[m.end() + e:]
        notes.append(f"inline call parameterized {len(params)} value(s): {args}")
        changed = True
        pos = m.end() + len(lit)
    return (out if changed else None), notes


def apply(workdir):
    """Rewrite every eligible Python file. Returns (originals: {path: text}, notes)."""
    workdir = Path(workdir)
    originals = {}
    notes = []
    skip = {".venv", "venv", "site-packages", "node_modules", "build", "dist", ".git", "__pycache__", ".eggs"}
    files = [p for p in workdir.rglob("*.py") if not (set(p.parts) & skip) and not p.name.startswith("test")]
    tree_text = "\n".join(p.read_text(encoding="utf-8", errors="replace")[:4000] for p in files[:60]
                          if p.name in ("db.py", "database.py", "main.py", "app.py", "requirements.txt"))
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "f\"" not in text and "f'" not in text:
            continue
        driver = detect_driver(text, tree_text)
        if driver is None:
            continue
        new, file_notes = rewrite_source(text, driver)
        if new is None:
            continue
        originals[str(p)] = text
        p.write_text(new, encoding="utf-8")
        notes.extend(f"{p.relative_to(workdir)}: {n}" for n in file_notes)
    return originals, notes


def revert(originals):
    for path, text in originals.items():
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError:
            pass
