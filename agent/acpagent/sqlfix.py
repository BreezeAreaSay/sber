"""Mechanical rewrite of SQL built from user values into parameterized queries.

Rewriting `f"... WHERE name = '{x}'"` (or the same built with %, .format() or +)
into `"... WHERE name = $1"` plus a bound argument is a transformation, not a
judgement call, and it is exactly what a small model gets wrong (it adds the
placeholder and forgets the argument, or drops the LIKE wildcards). The rewrite is
only kept if the project's tests still pass; anything it cannot handle safely
(identifiers, IN-lists, joins built from input) is left to the model.
"""

import re
from pathlib import Path

_SQL_KW = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|LIKE|ORDER BY|SET|RETURNING)\b")
# inside an f-string: `'{expr}'`, `'%{expr}%'`, `"{expr}"`, bare `{expr}`
_PLACEHOLDER = re.compile(r"'(%?)\{([^{}:!]+?)\}(%?)'|\"(%?)\{([^{}:!]+?)\}(%?)\"|(?<![{'\"%])\{([^{}:!]+?)\}(?![}'\"%])")
_PCT_PLACEHOLDER = re.compile(r"'(%?)%[sd](%?)'|(?<!%)%[sd]")
_FMT_PLACEHOLDER = re.compile(r"'(%?)\{(\d*)\}(%?)'|(?<![{'\"%])\{(\d*)\}(?![}'\"%])")
_CALL_METHODS = r"(?:fetch|fetchrow|fetchval|fetchall|fetchone|execute|executemany|query|run)"
_IDENT_TAIL = ("FROM", "INTO", "UPDATE", "JOIN", "ORDER BY", "BY", "TABLE", "SET", "ASC", "DESC", ",", "SELECT")


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


# ---- tokenizer for the right-hand side of an assignment ------------------------------------

def _read_string(src, i):
    """src[i] is a quote (prefix already consumed). Return (end_index_exclusive, body)."""
    q = src[i]
    if src.startswith(q * 3, i):
        end = src.find(q * 3, i + 3)
        if end < 0:
            return None
        return end + 3, src[i + 3:end]
    j = i + 1
    buf = []
    while j < len(src):
        c = src[j]
        if c == "\\":
            buf.append(src[j:j + 2])
            j += 2
            continue
        if c == q:
            return j + 1, "".join(buf)
        if c == "\n":
            return None
        buf.append(c)
        j += 1
    return None


def _balanced(src, i, open_ch="(", close_ch=")"):
    """src[i] == open_ch; return index after the matching close."""
    depth = 0
    j = i
    in_q = None
    while j < len(src):
        c = src[j]
        if in_q:
            if c == "\\":
                j += 2
                continue
            if c == in_q:
                in_q = None
        elif c in "\"'":
            in_q = c
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return None


def _tokenize_rhs(rhs: str):
    """Tokens: ('str', is_f, body) | ('plus',) | ('pct', operand_text) | ('format', args_text) | ('expr', text)."""
    toks = []
    i = 0
    n = len(rhs)
    while i < n:
        c = rhs[i]
        if c.isspace() or c == "\\":
            i += 1
            continue
        if c == "(":
            # grouping parenthesis around the whole expression or a part of it
            i += 1
            continue
        if c == ")":
            i += 1
            continue
        m = re.match(r"([fFrRbBuU]{0,2})(['\"])", rhs[i:])
        if m:
            prefix = m.group(1).lower()
            if "b" in prefix:
                return None
            start = i + len(m.group(1))
            r = _read_string(rhs, start)
            if r is None:
                return None
            end, body = r
            toks.append(("str", "f" in prefix, body))
            i = end
            rest = rhs[i:]
            fm = re.match(r"\s*\.format\(", rest)
            if fm:
                open_idx = i + fm.end() - 1
                close = _balanced(rhs, open_idx)
                if close is None:
                    return None
                toks.append(("format", rhs[open_idx + 1:close - 1]))
                i = close
            continue
        if c == "+":
            toks.append(("plus",))
            i += 1
            continue
        if c == "%":
            i += 1
            while i < n and rhs[i].isspace():
                i += 1
            if i < n and rhs[i] == "(":
                close = _balanced(rhs, i)
                if close is None:
                    return None
                toks.append(("pct", rhs[i + 1:close - 1]))
                i = close
            else:
                m2 = re.match(r"[\w.]+(?:\([^()]*\))?(?:\[[^\]]*\])?", rhs[i:])
                if not m2:
                    return None
                toks.append(("pct", m2.group(0)))
                i += m2.end()
            continue
        m3 = re.match(r"str\(", rhs[i:])
        if m3:
            close = _balanced(rhs, i + 3)
            if close is None:
                return None
            toks.append(("expr", rhs[i + 4:close - 1].strip()))
            i = close
            continue
        m4 = re.match(r"[A-Za-z_][\w.]*(?:\([^()]*\))?(?:\[[^\[\]]*\])?", rhs[i:])
        if m4:
            toks.append(("expr", m4.group(0)))
            i += m4.end()
            continue
        return None
    return toks


def _split_args(text: str):
    """Split a comma-separated argument list at depth 0."""
    out, depth, cur, in_q = [], 0, [], None
    for ch in text:
        if in_q:
            cur.append(ch)
            if ch == in_q:
                in_q = None
            continue
        if ch in "\"'":
            in_q = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _safe_expr(expr: str) -> bool:
    expr = expr.strip()
    return bool(expr) and "join(" not in expr and not expr.startswith(("'", '"')) and "{" not in expr


def _rewrite_fstring(inner: str, driver, counter, params):
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
        if not _safe_expr(expr):
            return None
        before = inner[:m.start()].rstrip().upper()
        if m.group(2) is None and m.group(5) is None:
            if before.endswith(_IDENT_TAIL):
                return None
            if re.search(r"(?:=|LIKE|IN|>|<|,|\()\s*$", before) is None:
                return None
        counter[0] += 1
        params.append(f'f"{pre}{{{expr}}}{post}"' if (pre or post) else expr)
        out.append(inner[pos:m.start()])
        out.append(driver.placeholder(counter[0]))
        pos = m.end()
    out.append(inner[pos:])
    body = "".join(out)
    if "{" in body.replace("{{", "").replace("}}", ""):
        return None
    return body.replace("{{", "{").replace("}}", "}")


def _rewrite_pct(body: str, args, driver, counter, params):
    out, pos, k = [], 0, 0
    for m in _PCT_PLACEHOLDER.finditer(body):
        if k >= len(args):
            return None
        expr = args[k].strip()
        k += 1
        if not _safe_expr(expr):
            return None
        pre, post = (m.group(1) or ""), (m.group(2) or "")
        counter[0] += 1
        params.append(f'f"{pre}{{{expr}}}{post}"' if (pre or post) else expr)
        out.append(body[pos:m.start()])
        out.append(driver.placeholder(counter[0]))
        pos = m.end()
    if k != len(args):
        return None
    out.append(body[pos:])
    return "".join(out).replace("%%", "%")


def _rewrite_format(body: str, args, driver, counter, params):
    out, pos, k = [], 0, 0
    for m in _FMT_PLACEHOLDER.finditer(body):
        idx_txt = m.group(2) if m.group(2) is not None else m.group(4)
        if idx_txt:
            idx = int(idx_txt)
        else:
            idx = k
            k += 1
        if idx >= len(args):
            return None
        expr = args[idx].strip()
        if not _safe_expr(expr) or "=" in expr.split("(")[0]:
            return None
        pre, post = (m.group(1) or ""), (m.group(3) or "")
        counter[0] += 1
        params.append(f'f"{pre}{{{expr}}}{post}"' if (pre or post) else expr)
        out.append(body[pos:m.start()])
        out.append(driver.placeholder(counter[0]))
        pos = m.end()
    out.append(body[pos:])
    res = "".join(out)
    if "{" in res.replace("{{", "").replace("}}", ""):
        return None
    return res.replace("{{", "{").replace("}}", "}")


def build_query(rhs: str, driver):
    """Turn an SQL-building expression into (sql_literal_body, [param exprs]) or None."""
    toks = _tokenize_rhs(rhs)
    if not toks:
        return None
    counter, params = [0], []
    pieces = []          # ('sql', text) | ('param',)
    i = 0
    while i < len(toks):
        t = toks[i]
        if t[0] == "str":
            nxt = toks[i + 1] if i + 1 < len(toks) else None
            if nxt and nxt[0] == "pct":
                args = _split_args(nxt[1]) if "," in nxt[1] or nxt[1].strip().startswith("(") else [nxt[1].strip().strip("()")]
                body = _rewrite_pct(t[2], args, driver, counter, params)
                if body is None:
                    return None
                pieces.append(("sql", body))
                i += 2
                continue
            if nxt and nxt[0] == "format":
                body = _rewrite_format(t[2], _split_args(nxt[1]), driver, counter, params)
                if body is None:
                    return None
                pieces.append(("sql", body))
                i += 2
                continue
            if t[1]:
                body = _rewrite_fstring(t[2], driver, counter, params)
                if body is None:
                    return None
                pieces.append(("sql", body))
            else:
                pieces.append(("sql", t[2]))
            i += 1
            continue
        if t[0] == "plus":
            i += 1
            continue
        if t[0] == "expr":
            if not _safe_expr(t[1]):
                return None
            counter[0] += 1
            params.append(t[1])
            pieces.append(("param",))
            i += 1
            continue
        return None
    # assemble: a concatenated expression usually sits between quotes: "... = '" + x + "'"
    sql = ""
    for j, p in enumerate(pieces):
        if p[0] == "sql":
            sql += p[1]
        else:
            n = sql.count("$") if driver.style == "$n" else None
            # strip a quote that wraps the concatenated value
            wrapped = sql.endswith("'")
            if wrapped:
                sql = sql[:-1]
            k = sum(1 for q in pieces[:j] if q[0] == "param") + 1
            # placeholders inside f-strings before this point were numbered already; use the
            # running total of parameters instead
            sql += driver.placeholder(len([x for x in params[:k]]) if False else _param_index(pieces, j, params))
            if wrapped and j + 1 < len(pieces) and pieces[j + 1][0] == "sql" and pieces[j + 1][1].startswith("'"):
                pieces[j + 1] = ("sql", pieces[j + 1][1][1:])
    if not params or not _SQL_KW.search(sql):
        return None
    if "{" in sql or "%s" in sql and driver.style != "%s":
        return None
    return sql, params


def _param_index(pieces, j, params):
    """Index (1-based) of the parameter produced by the j-th piece."""
    # parameters are appended in reading order; count placeholders created before piece j
    count = 0
    for q in pieces[:j]:
        if q[0] == "param":
            count += 1
        else:
            count += len(re.findall(r"\$\d+|\?|%s", q[1]))
    return count + 1


def _statement_end(src: str, start: int) -> int:
    depth, i, n, in_q = 0, start, len(src), None
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


def _literal(sql: str) -> str:
    return '"' + sql.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rewrite_source(src: str, driver):
    """Rewrite one file. Returns (new_src or None, notes)."""
    notes = []
    out = src
    changed = False
    # 1. `var = <sql expression>` followed by `<obj>.<method>(var)`
    assign_re = re.compile(r"^(?P<indent>[ \t]*)(?P<var>\w+)\s*(?P<op>=|\+=)\s*(?=\(?\s*[fFrRuU]?['\"])", re.M)
    pos = 0
    while True:
        m = assign_re.search(out, pos)
        if not m:
            break
        stmt_end = _statement_end(out, m.start())
        rhs = out[m.end():stmt_end]
        if m.group("op") == "+=":
            pos = stmt_end + 1
            continue
        res = build_query(rhs, driver)
        if res is None:
            pos = stmt_end + 1
            continue
        sql, params = res
        var = m.group("var")
        tail = out[stmt_end:]
        call = re.search(r"\b(?:await\s+)?[\w.]+\." + _CALL_METHODS + r"\(\s*" + re.escape(var) + r"\s*(\)|,)", tail)
        if not call or call.group(1) == ",":
            pos = stmt_end + 1
            continue
        args = ", ".join(params)
        arg_text = f"({args},)" if driver.tuple_args else args
        new_stmt = f"{m.group('indent')}{var} = {_literal(sql)}"
        call_start, call_end = stmt_end + call.start(), stmt_end + call.end()
        new_call = out[call_start:call_end][:-1] + ", " + arg_text + ")"
        out = out[:m.start()] + new_stmt + out[stmt_end:call_start] + new_call + out[call_end:]
        notes.append(f"{var}: parameterized {len(params)} value(s): {args}")
        changed = True
        pos = m.start() + len(new_stmt) + 1
    # 2. inline: `<obj>.<method>(<sql expression>)`
    inline_re = re.compile(r"(\b(?:await\s+)?[\w.]+\." + _CALL_METHODS + r"\(\s*)(?=[fFrRuU]?['\"])")
    pos = 0
    while True:
        m = inline_re.search(out, pos)
        if not m:
            break
        close = _balanced(out, m.end() - 1)
        if close is None:
            pos = m.end()
            continue
        inner = out[m.end():close - 1]
        res = build_query(inner, driver)
        if res is None:
            pos = m.end()
            continue
        sql, params = res
        args = ", ".join(params)
        arg_text = f"({args},)" if driver.tuple_args else args
        replacement = _literal(sql) + ", " + arg_text
        out = out[:m.end()] + replacement + out[close - 1:]
        notes.append(f"inline call parameterized {len(params)} value(s): {args}")
        changed = True
        pos = m.end() + len(replacement)
    # 3. `conditions.append(f"col = '{x}'")` next to a `params` list used with `${len(params)}`
    if "len(params)" in out or "params.append" in out:
        cond_re = re.compile(r"^(?P<indent>[ \t]*)(?P<lst>\w+)\.append\(\s*f(['\"])(?P<body>[^\n]*?)\3\s*\)\s*$", re.M)
        pos = 0
        while True:
            m = cond_re.search(out, pos)
            if not m:
                break
            body = m.group("body")
            if "len(params)" in body or "{" not in body:
                pos = m.end()
                continue
            counter, params = [0], []
            new_body = _rewrite_fstring(body, Driver("$n", False), counter, params)
            if new_body is None or len(params) != 1:
                pos = m.end()
                continue
            new_body = new_body.replace("$1", "${len(params)}")
            ind = m.group("indent")
            repl = f"{ind}params.append({params[0]})\n{ind}{m.group('lst')}.append(f\"{new_body}\")"
            out = out[:m.start()] + repl + out[m.end():]
            notes.append(f"{m.group('lst')}.append: parameterized {params[0]} via params list")
            changed = True
            pos = m.start() + len(repl)
    return (out if changed else None), notes


def apply(workdir):
    """Rewrite every eligible Python file. Returns (originals: {path: text}, notes)."""
    workdir = Path(workdir)
    originals, notes = {}, []
    skip = {".venv", "venv", "site-packages", "node_modules", "build", "dist", ".git", "__pycache__", ".eggs"}
    files = [p for p in workdir.rglob("*.py") if not (set(p.parts) & skip) and not p.name.startswith("test")]
    tree_text = "\n".join(p.read_text(encoding="utf-8", errors="replace")[:4000] for p in files[:60]
                          if p.name in ("db.py", "database.py", "main.py", "app.py", "requirements.txt", "models.py"))
    for p in files:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
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
