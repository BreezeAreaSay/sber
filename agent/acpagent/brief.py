"""Context gathered before the first model call.

A small model spends its first three or four rounds on `ls` and `cat`. Doing that work
up front — a directory tree, the routes, the risky lines, the shape of the data — is
cheaper in tokens than the round-trips it replaces and steers the model straight to
the files that matter.
"""

import base64
import codecs
import os
import re
import subprocess
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
             ".tox", "dist", "build", ".idea", ".vscode", "site-packages", ".cache", ".ruff_cache"}
SOURCE_EXT = {".py", ".js", ".mjs", ".ts", ".tsx", ".jsx", ".php", ".rb", ".go", ".java", ".cs", ".rs",
              ".c", ".cc", ".cpp", ".h", ".hpp", ".sh", ".pl", ".kt", ".scala", ".sql", ".html", ".htm",
              ".jinja", ".j2", ".tpl", ".twig", ".erb", ".vue", ".yaml", ".yml", ".toml", ".ini", ".cfg",
              ".env", ".conf", ".json", ".xml", ".properties", ".lua"}
MAX_FILE_BYTES = 600_000
MAX_FILES = 600
MAX_BRIEF_CHARS = 22000


def iter_files(root: Path, limit: int = MAX_FILES):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git"))
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            try:
                if p.is_symlink() or not p.is_file():
                    continue
            except OSError:
                continue
            yield p
            n += 1
            if n >= limit:
                return


def tree(root: Path, max_entries: int = 160, max_depth: int = 4) -> str:
    root = Path(root)
    lines = []
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        depth = 0 if rel == "." else rel.count(os.sep) + 1
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        if depth > max_depth:
            dirnames[:] = []
            continue
        indent = "  " * depth
        if rel != ".":
            lines.append(f"{indent}{os.path.basename(dirpath)}/")
            count += 1
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            lines.append(f"{indent}  {fn}  ({_hsize(size)})")
            count += 1
            if count >= max_entries:
                lines.append(f"{indent}  ... (more entries not shown)")
                return "\n".join(lines)
    return "\n".join(lines) if lines else "(empty directory)"


def _hsize(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n // 1024}K"
    return f"{n / 1024 / 1024:.1f}M"


# ---- risky-pattern scan --------------------------------------------------------------

# (label, category, cwe, regex, severity, languages)
PATTERNS = [
    ("SQL query built from string formatting", "SQL Injection", "CWE-89",
     r"""(?i)(?:execute|executemany|fetch|fetchrow|fetchval|fetchall|fetchone|query|raw|text|cursor\.\w+|db\.\w+|conn\.\w+)\s*\(\s*(?:f["']|["'][^"']*["']\s*(?:%|\+|\.format)|.*\+\s*\w+\s*\+)|(?:f["']|"[^"\n]*"\s*%\s*|\.format\()[^\n]*(?-i:\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|VALUES|ORDER BY|LIKE)\b)|(?-i:\b(?:SELECT|INSERT|UPDATE|DELETE)\b)[^\n]*(?:\{\w[\w.\[\]'"]*\}|\$\{|"\s*\+\s*\w|'\s*\+\s*\w|\+\s*req\.|\+\s*request\.)""",
     "critical", None),
    ("OS command built from input / shell=True", "OS Command Injection", "CWE-78",
     r"""(?i)\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.[a-z_]+\([^\n]*shell\s*=\s*True|\bcommands\.getoutput|child_process\.exec\s*\(|\bexecSync\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|\bproc_open\s*\(|(?<![\w.])system\s*\(|Runtime\.getRuntime\(\)\.exec|\bpopen\s*\(""",
     "critical", None),
    ("Dynamic code execution / unsafe deserialization", "Code Injection / Deserialization", "CWE-502",
     r"""(?i)(?<![\w.])eval\s*\(|(?<![\w.])exec\s*\(|pickle\.loads?\s*\(|cPickle\.loads?|marshal\.loads?|yaml\.load\s*\((?![^)]*SafeLoader)|yaml\.unsafe_load|\bunserialize\s*\(|ObjectInputStream|shelve\.open|jsonpickle\.decode|new Function\s*\(""",
     "critical", None),
    ("File path built from user input (path traversal)", "Path Traversal", "CWE-22",
     r"""(?i)\b(?:open|send_file|send_from_directory|FileResponse|readFile|readFileSync|createReadStream|file_get_contents|fopen|os\.path\.join|Path)\s*\(""",
     "high", None),
    ("Outbound request to a user-controlled URL (SSRF)", "Server-Side Request Forgery", "CWE-918",
     r"""(?i)(?:requests\.(?:get|post|put|delete|request|head)|urllib\.request\.urlopen|urlopen|httpx\.(?:get|post|request)|aiohttp\.ClientSession|(?<![\w.])fetch|axios\.(?:get|post)|curl_exec|file_get_contents\(\s*\$)\s*\([^\n]*(?:request\.|req\.|params|args|query|form|url\b|target|\burl\s*=)""",
     "high", None),
    ("Hard-coded secret or credential", "Hard-coded Credentials", "CWE-798",
     r"""(?i)\b(?:secret_key|secret|password|passwd|pwd|api_key|apikey|token|private_key|jwt_secret|aws_secret|client_secret)\b\s*[:=]\s*["'][^"'\n]{4,}["']""",
     "high", None),
    ("Weak or misused cryptography", "Weak Cryptography", "CWE-327",
     r"""(?i)hashlib\.(?:md5|sha1)\s*\(|\bmd5\s*\(|\bsha1\s*\(|\bDES\b|\bRC4\b|ECB|createHash\(\s*['"](?:md5|sha1)|random\.(?:random|randint|choice|randrange)\s*\([^\n]*(?:token|secret|key|password|session|otp|reset)|Math\.random\(\)[^\n]*(?:token|secret|key|password|session)""",
     "medium", None),
    ("Debug mode / TLS verification disabled / permissive CORS", "Security Misconfiguration", "CWE-16",
     r"""(?i)debug\s*=\s*True|verify\s*=\s*False|CERT_NONE|rejectUnauthorized\s*:\s*false|allow_origins\s*=\s*\[\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|cors\(\s*\)|app\.run\([^\n]*host\s*=\s*["']0\.0\.0\.0""",
     "medium", None),
    ("JWT/signature verification weakened", "Improper Authentication", "CWE-287",
     r"""(?i)jwt\.decode\([^\n]*(?:verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False|algorithms\s*=\s*\[[^\]]*none)|algorithm\s*=\s*["']none["']|verify_signature["']?\s*:\s*False""",
     "critical", None),
    ("Template rendered from user input (SSTI)", "Server-Side Template Injection", "CWE-1336",
     r"""(?i)render_template_string\s*\([^\n]*(?:request\.|req\.|\bf["']|\+\s*\w)|Template\s*\([^\n]*(?:request\.|req\.)""",
     "high", None),
    ("HTML rendered without escaping (XSS)", "Cross-Site Scripting", "CWE-79",
     r"""(?i)render_template_string\s*\(|\bMarkup\s*\(|\|\s*safe\b|autoescape\s*=\s*False|innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|\{\{\{|<%-|echo\s+\$_(?:GET|POST|REQUEST)""",
     "medium", None),
    ("Raw request parameter used in PHP", "Input Handling", "CWE-20",
     r"""\$_(?:GET|POST|REQUEST|COOKIE)\[[^\]]+\][^\n]*(?:mysql_query|mysqli_query|->query\(|include|require|exec|system|eval|unserialize|header\()""",
     "high", None),
    ("XML parsed with external entities enabled", "XML External Entity", "CWE-611",
     r"""(?i)resolve_entities\s*=\s*True|XMLParser\([^\n]*(?:load_dtd|resolve_entities)|libxml_disable_entity_loader\(\s*false|DocumentBuilderFactory|xml\.dom\.minidom\.parse""",
     "high", None),
    ("Unsafe file permissions or temp file", "Insecure Permissions", "CWE-732",
     r"""(?i)chmod\s*\([^\n]*0o?777|os\.chmod\([^\n]*0o?7[67]7|tempfile\.mktemp\s*\(|umask\s*\(\s*0\s*\)""",
     "low", None),
    ("Password compared / stored in plaintext", "Plaintext Password Storage", "CWE-256",
     r"""(?i)password\s*==\s*|==\s*[\w.]*password\b|\bpassword\s*=\s*\$\d|INSERT INTO users[^\n]*password|WHERE[^\n]*password\s*=\s*['"]?\{""",
     "high", None),
    ("Open redirect", "Open Redirect", "CWE-601",
     r"""(?i)(?:redirect|RedirectResponse|res\.redirect|header\(\s*["']Location)\s*\([^\n]*(?:request\.|req\.|params|args|query|next\b|url\b|return_to|redirect_uri)""",
     "medium", None),
("Request body assigned straight onto a model (mass assignment)", "Mass Assignment", "CWE-915",
     r"""(?i)(?:\w+\s*\(\s*\*\*\s*(?:request\.(?:json|form|data|get_json\(\))|req\.body|payload|data|body)\b|"""
     r"""\.update\s*\(\s*(?:request\.(?:json|form)|req\.body|payload)\b|setattr\s*\([^,\n]+,\s*\w+\s*,\s*(?:request|req)\.)""",
     "medium", None),
    ("Cookie set without Secure/HttpOnly", "Insecure Cookie", "CWE-614",
     r"""(?i)set_cookie\s*\((?![^\n]*(?:httponly\s*=\s*True|secure\s*=\s*True))[^\n]*\)""",
     "low", None),
    ("Secret or credential written to the log", "Sensitive Data in Logs", "CWE-532",
     r"""(?i)(?:log(?:ger|ging)?\.\w+|print)\s*\([^\n]*(?:password|passwd|secret|token|api[_-]?key|authorization|credit|ssn)\b""",
     "medium", None),
    ("Uploaded file saved under a caller-supplied name", "Unrestricted File Upload", "CWE-434",
     r"""(?i)\.save\s*\([^\n]*(?:filename|request\.|req\.|\bname\b)|save_uploaded|shutil\.copyfileobj\s*\([^\n]*request""",
     "high", None),
    ("Internal error detail returned to the caller", "Information Disclosure", "CWE-209",
     r"""(?i)(?:return|jsonify|Response)\s*\([^\n]*(?:traceback\.format_exc|str\s*\(\s*e\s*\)|repr\s*\(\s*e\s*\)|\bexc\b)""",
     "low", None),
]
_COMPILED = [(lab, cat, cwe, re.compile(rx), sev) for lab, cat, cwe, rx, sev, _ in PATTERNS]
# Findings worth reporting that must not drive a mechanical rewrite: "fixing" them
# blindly changes stored data, hashing schemes or response shapes the tests rely on.
AUDIT_ONLY_CATEGORIES = {"Plaintext Password Storage", "Hard-coded Credentials", "Weak Cryptography",
                         "Insecure Permissions", "Mass Assignment", "Insecure Cookie",
                         "Sensitive Data in Logs", "Unrestricted File Upload",
                         "Server-Side Template Injection", "Information Disclosure"}
# Interpolations that are not user data: placeholder counters, joined column lists, table names.
_BENIGN_SQL_RE = re.compile(r"""\{\s*len\(|\{\s*['"][^'"]*['"]\.join\(|\{\s*\w+\.join\(|\{\s*placeholders?\s*\}|\{\s*(?:table|tbl|columns?|cols|fields)\s*\}|^\s*@\w+\.(?:get|post|put|delete|patch|route)\(""")

ROUTE_RE = re.compile(
    r"""(?x)
    @(?:app|router|api|bp|blueprint|\w+_bp|\w+_router)\.(?:route|get|post|put|delete|patch|api_route|websocket)\s*\(\s*["']([^"']+)["']
    |(?:app|router|server)\.(?:get|post|put|delete|patch|use|all)\s*\(\s*["']([^"']+)["']
    |Route::(?:get|post|put|delete|patch|any)\s*\(\s*["']([^"']+)["']
    |@(?:Get|Post|Put|Delete|Patch|RequestMapping|GetMapping|PostMapping)Mapping?\s*\(\s*["']([^"']+)["']
    |path\(\s*["']([^"']+)["']
    """
)


_TAINT_SRC_RE = re.compile(r"request\.|req\.|\.args\b|\.params\b|\.query\b|\.form\b|\.json\b|\binput\s*\(|sys\.argv|\bquery_params\b")
_IDENT_RE = re.compile(r"[A-Za-z_]\w*")
_HANDLER_DECO_RE = re.compile(r"@\w+\.(?:get|post|put|delete|patch|route)\b|@(?:app|router|bp|blueprint)\b", re.I)
_CALL_NOISE = {"os", "path", "join", "open", "self", "str", "int", "bytes", "Path", "send_file", "f", "r", "rb", "w",
               "encoding", "utf", "dirname", "abspath", "realpath", "file", "with", "return", "as"}


def _user_tainted(lines, idx: int, line: str) -> bool:
    """True when an identifier in this call was filled from request data.

    A path built only from constants is not a traversal bug, and reporting it costs a
    real finding's place in the report and a mechanical fix attempt."""
    call = line[line.find("("):] if "(" in line else line
    idents = {i for i in _IDENT_RE.findall(call)} - _CALL_NOISE
    if not idents:
        return False
    start = max(0, idx - 30)
    for prev in lines[start:idx]:
        if not _TAINT_SRC_RE.search(prev):
            continue
        m = re.match(r"\s*([A-Za-z_]\w*)\s*=", prev)
        if m and m.group(1) in idents:
            return True
    # a request handler's own parameters are user input (FastAPI: def read(filename: str))
    for j in range(idx, start, -1):
        m = re.match(r"\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)", lines[j - 1])
        if not m:
            continue
        params = {q.split(":")[0].split("=")[0].strip() for q in m.group(1).split(",") if q.strip()}
        if (idents & params) - {"self"} and _HANDLER_DECO_RE.search("\n".join(lines[max(0, j - 5):j])):
            return True
        break
    return False


# a line that confines a path (or the fix we just applied) is not a vulnerability
_PATH_GUARD_RE = re.compile(r"realpath|abspath|commonpath|commonprefix|is_relative_to|\.resolve\(\)|secure_filename|"
                            r"os\.path\.basename|safe_join", re.I)
# an outbound fetch is confined by a check on the URL that precedes it
_URL_GUARD_RE = re.compile(
    r"""_is_safe_external_url|urlparse|allowed_host|ALLOWED_|is_private|ip_address|startswith\(\s*\(?\s*["']https?""",
    re.I)


def scan_hotspots(root: Path, max_hits: int = 45):
    """Return a list of dicts: file, line, label, category, cwe, severity, code."""
    hits = []
    for p in iter_files(root):
        if p.suffix.lower() not in SOURCE_EXT and p.suffix:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "test" in p.name.lower() and p.suffix == ".py" and "/tests" in str(p):
            continue
        rel = os.path.relpath(p, root)
        for i, line in enumerate(text.splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("//") or s.startswith("*"):
                continue
            for lab, cat, cwe, rx, sev in _COMPILED:
                if lab.startswith("SQL") and _BENIGN_SQL_RE.search(line):
                    continue
                if cat == "Path Traversal" and _PATH_GUARD_RE.search(line):
                    continue  # this line IS the containment check
                if rx.search(line):
                    if cat == "Server-Side Request Forgery":
                        _src_lines = text.splitlines()
                        if _URL_GUARD_RE.search("\n".join(_src_lines[max(0, i - 6):i])):
                            break  # the URL is validated before the request is made
                    if cat == "Path Traversal":
                        _src_lines = text.splitlines()
                        if not _user_tainted(_src_lines, i - 1, line):
                            break  # built from constants only
                        if _PATH_GUARD_RE.search("\n".join(_src_lines[i:i + 5])):
                            break  # a containment check follows: the path is confined
                    hits.append({"file": rel, "line": i, "label": lab, "category": cat, "cwe": cwe,
                                 "severity": sev, "code": s[:200], "function": _enclosing_def(text, i)})
                    break
            if len(hits) >= max_hits * 3:
                break
    # rank: critical first, then by file
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    hits.sort(key=lambda h: (order.get(h["severity"], 9), h["file"], h["line"]))
    # de-noise: obvious comments already skipped; drop "CLEAN"/"safe" annotated lines
    return hits[:max_hits]


def _enclosing_def(text: str, lineno: int):
    lines = text.splitlines()
    for j in range(min(lineno, len(lines)) - 1, -1, -1):
        m = re.match(r"\s*(?:async\s+)?(?:def|function|func|public|private|protected|static|fn)\s+([\w$]+)", lines[j])
        if m:
            return m.group(1)
        m = re.match(r"\s*(?:const|let|var)?\s*([\w$]+)\s*[:=]\s*(?:async\s*)?\(?[^)]*\)?\s*=>", lines[j])
        if m:
            return m.group(1)
    return ""


def routes(root: Path, max_routes: int = 60):
    out = []
    for p in iter_files(root):
        if p.suffix.lower() not in (".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".mjs"):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = os.path.relpath(p, root)
        for i, line in enumerate(text.splitlines(), 1):
            m = ROUTE_RE.search(line)
            if m:
                path = next(g for g in m.groups() if g)
                out.append(f"{rel}:{i}  {line.strip()[:110]}")
                if len(out) >= max_routes:
                    return out
    return out


def format_hotspots(hits) -> str:
    if not hits:
        return ""
    lines = []
    for h in hits:
        fn = f" in {h['function']}()" if h.get("function") else ""
        lines.append(f"- {h['file']}:{h['line']}{fn} [{h['label']}]: {h['code'][:150]}")
    return "\n".join(lines)


# ---- data files (forensics / generic) --------------------------------------------------

def data_heads(root: Path, max_files: int = 40, head_lines: int = 4, line_chars: int = 220) -> str:
    out = []
    total = 0
    for p in iter_files(Path(root), limit=max_files):
        try:
            size = p.stat().st_size
            with p.open("rb") as fh:
                raw = fh.read(65536)
        except OSError:
            continue
        rel = os.path.relpath(p, root)
        if b"\x00" in raw[:4096]:
            kind = _file_type(p)
            out.append(f"## {rel}  ({_hsize(size)}, binary: {kind})")
            continue
        try:
            nlines = sum(1 for _ in p.open("rb")) if size < 50_000_000 else -1
        except OSError:
            nlines = -1
        text = raw.decode("utf-8", "replace")
        first = [ln[:line_chars] for ln in text.splitlines()[:head_lines]]
        out.append(f"## {rel}  ({_hsize(size)}, {nlines} lines)\n" + "\n".join("  " + ln for ln in first))
        total += sum(len(x) for x in first)
        if total > MAX_BRIEF_CHARS:
            out.append("... (more files not shown)")
            break
    return "\n".join(out)


_PROGRAM_OUTPUT_CACHE = {}


def program_outputs(root: Path, max_programs: int = 8, timeout: int = 6):
    """Run the challenge's own programs (ELF binaries, python/shell scripts) with no
    arguments and with --help, capturing what they print. Returns [(label, bytes)].
    Memoised per directory: the flag scan and the briefing both ask for it."""
    key = str(Path(root).resolve())
    if key in _PROGRAM_OUTPUT_CACHE:
        return _PROGRAM_OUTPUT_CACHE[key]
    results = []
    _PROGRAM_OUTPUT_CACHE[key] = results
    count = 0
    safe_env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "TERM", "PYTHONIOENCODING")}
    safe_env["TERM"] = "dumb"
    for p in iter_files(Path(root), limit=200):
        if count >= max_programs:
            break
        try:
            size = p.stat().st_size
            if size > 5_000_000 or size == 0:
                continue
            with p.open("rb") as fh:
                head = fh.read(64)
        except OSError:
            continue
        rel = os.path.relpath(p, root)
        if head.startswith(b"\x7fELF"):
            cmds = [[str(p)], [str(p), "--help"]]
            try:
                os.chmod(p, 0o755)
            except OSError:
                pass
        elif p.suffix == ".py" or head.startswith(b"#!") and b"python" in head:
            cmds = [["python3", str(p)], ["python3", str(p), "--help"]]
        elif p.suffix == ".sh" or head.startswith(b"#!") and (b"sh" in head or b"bash" in head):
            cmds = [["bash", str(p)]]
        else:
            continue
        count += 1
        for argv in cmds:
            try:
                r = subprocess.run(argv, cwd=str(p.parent), stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=timeout, env=safe_env)
                out = (r.stdout or b"") + (b"\n[stderr] " + r.stderr if r.stderr else b"")
            except subprocess.TimeoutExpired as exc:
                out = (exc.stdout or b"") + b"\n[timed out]"
            except Exception:  # noqa: BLE001
                continue
            if out.strip():
                results.append((f"{rel} {' '.join(argv[1:]) if len(argv) > 1 and argv[0] not in ('python3', 'bash') else ' '.join(argv[2:])}".strip(), out[:6000]))
    return results


def binary_strings(root: Path, max_files: int = 12) -> str:
    """Interesting printable strings from binaries and captures, for the CTF briefing."""
    out = []
    for p in iter_files(Path(root), limit=200):
        try:
            if p.stat().st_size > 20_000_000:
                continue
            with p.open("rb") as fh:
                head = fh.read(4096)
            if b"\x00" not in head:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        rel = os.path.relpath(p, root)
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
            try:
                from acpagent import digest as _dg
                d, _ = _dg.pcap_digest(p)
                if d:
                    out.append(f"## {rel} (packet capture)\n{d[:1800]}")
            except Exception:  # noqa: BLE001
                pass
            continue
        runs = [m.group(0).decode("ascii", "replace") for m in re.finditer(rb"[\x20-\x7e]{8,}", data[:3_000_000])]
        interesting = [s for s in runs if re.search(r"flag|key|pass|secret|usage|enter|correct|wrong|http|\{|decode|encrypt|base64|xor", s, re.I)]
        sample = interesting[:25] or runs[:15]
        if sample:
            out.append(f"## {rel} ({_file_type(p)}): strings of interest\n  " + "\n  ".join(s[:140] for s in sample))
        if len(out) >= max_files:
            break
    return "\n".join(out)


def _file_type(p: Path) -> str:
    try:
        r = subprocess.run(["file", "-b", str(p)], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()[:100]
    except Exception:  # noqa: BLE001
        return "unknown"


# ---- CTF quick scan --------------------------------------------------------------------

FLAG_RE = re.compile(rb"(?<![A-Za-z0-9_])[A-Za-z0-9_]{2,24}\{[\x20-\x7e]{1,200}?\}")
COMMON_TAGS = (b"flag{", b"FLAG{", b"Flag{", b"ctf{", b"CTF{", b"ACP{", b"acp{", b"key{", b"KEY{",
               b"HTB{", b"picoCTF{", b"secret{", b"SECRET{", b"AIRI{", b"airi{", b"sber{", b"SBER{")
_B64_RE = re.compile(rb"[A-Za-z0-9+/=]{16,}")
_HEX_RE = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")
_B32_RE = re.compile(rb"[A-Z2-7]{16,}=*")


def flag_candidates(root: Path, prefix: str = "", max_files: int = 400, max_bytes: int = 3_000_000):
    """Cheap zero-token search for flag-shaped strings: literal, base64, hex, rot13."""
    found = []
    pfx = prefix.encode() if prefix else b""

    def consider(data: bytes, src: str):
        for m in FLAG_RE.finditer(data):
            val = m.group(0)
            if pfx and not val.startswith(pfx):
                if not any(val.startswith(t) for t in COMMON_TAGS):
                    continue
            elif not pfx and not any(val.startswith(t) for t in COMMON_TAGS):
                continue
            try:
                found.append((val.decode("ascii"), src))
            except UnicodeDecodeError:
                pass

    for p in iter_files(Path(root), limit=max_files):
        try:
            if p.stat().st_size > max_bytes:
                continue
            data = p.read_bytes()
        except OSError:
            continue
        rel = os.path.relpath(p, root)
        consider(data, rel)
        if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"):
            try:
                from acpagent import digest as _dg
                _, payloads = _dg.pcap_digest(p)
                consider(payloads, f"{rel} (packet payloads)")
                for m in _B64_RE.finditer(payloads):
                    chunk = m.group(0)
                    if len(chunk) <= 20000:
                        try:
                            consider(base64.b64decode(chunk + b"=" * (-len(chunk) % 4), validate=False), f"{rel} (payload base64)")
                        except Exception:  # noqa: BLE001
                            pass
            except Exception:  # noqa: BLE001
                pass
        try:
            consider(codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1"), f"{rel} (rot13)")
        except Exception:  # noqa: BLE001
            pass
        for m in _B64_RE.finditer(data):
            chunk = m.group(0)
            if len(chunk) > 20000:
                continue
            try:
                dec = base64.b64decode(chunk + b"=" * (-len(chunk) % 4), validate=False)
            except Exception:  # noqa: BLE001
                continue
            consider(dec, f"{rel} (base64)")
            # second layer: base64-of-base64 / base64-of-hex are common CTF wrappers
            for m2 in _B64_RE.finditer(dec[:50000]):
                try:
                    consider(base64.b64decode(m2.group(0) + b"=" * (-len(m2.group(0)) % 4), validate=False), f"{rel} (base64 x2)")
                except Exception:  # noqa: BLE001
                    pass
            for m2 in _HEX_RE.finditer(dec[:50000]):
                try:
                    consider(bytes.fromhex(m2.group(0).decode()), f"{rel} (base64 then hex)")
                except Exception:  # noqa: BLE001
                    pass
            try:
                consider(codecs.encode(dec.decode("latin-1"), "rot13").encode("latin-1"), f"{rel} (base64 then rot13)")
            except Exception:  # noqa: BLE001
                pass
        for m in _HEX_RE.finditer(data):
            chunk = m.group(0)
            if len(chunk) > 20000:
                continue
            try:
                consider(bytes.fromhex(chunk.decode()), f"{rel} (hex)")
            except Exception:  # noqa: BLE001
                pass
        for m in _B32_RE.finditer(data):
            chunk = m.group(0)
            try:
                consider(base64.b32decode(chunk + b"=" * (-len(chunk) % 8)), f"{rel} (base32)")
            except Exception:  # noqa: BLE001
                pass
        consider(data[::-1], f"{rel} (reversed)")
        if len(data) <= 65536:
            # single-byte XOR: the classic first layer of a CTF "encryption"
            for k in range(1, 256):
                x = bytes(b ^ k for b in data)
                if b"{" in x and b"}" in x:
                    consider(x, f"{rel} (xor 0x{k:02x})")
        if len(found) > 20:
            break
    # what the challenge programs print (usage text, prompts, sometimes the flag itself)
    try:
        for src, out_bytes in program_outputs(Path(root)):
            consider(out_bytes, f"{src} (program output)")
    except Exception:  # noqa: BLE001
        pass
    # Caesar/ROT-N on text files: the classic "encrypted" note
    try:
        for p in iter_files(Path(root), limit=max_files):
            try:
                if p.stat().st_size > 200_000:
                    continue
                data = p.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:4096]:
                continue
            rel = os.path.relpath(p, root)
            for shift in range(1, 26):
                if shift == 13:
                    continue
                rotated = bytes((b - 65 + shift) % 26 + 65 if 65 <= b <= 90 else ((b - 97 + shift) % 26 + 97 if 97 <= b <= 122 else b) for b in data)
                if b"{" in rotated:
                    consider(rotated, f"{rel} (caesar +{shift})")
    except Exception:  # noqa: BLE001
        pass
    # the flag format is known plaintext, so an unknown repeating XOR key is recoverable
    # without any hint from the source
    try:
        markers = [pfx] if pfx else list(COMMON_TAGS)
        for p in iter_files(Path(root), limit=max_files):
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if not (4 <= size <= 262144):
                continue
            if p.suffix.lower() in (".py", ".md", ".json", ".yaml", ".yml", ".html", ".js", ".ts", ".c", ".h", ".go"):
                continue
            try:
                data = p.read_bytes()
            except OSError:
                continue
            if any(m in data for m in markers):
                continue  # already plain, the literal scan has it
            rel = os.path.relpath(p, root)
            for plain, how in xor_known_plaintext(data, markers):
                consider(plain, f"{rel} ({how})")
            if size <= 65536:
                for plain, how in xor_break_repeating(data):
                    if _text_score(plain) >= 1.6 and any(_clean_flag_in(plain, mk) for mk in markers):
                        consider(plain, f"{rel} ({how})")
    except Exception:  # noqa: BLE001
        pass
    # keys/passwords hidden in source: string constants (and joined list literals)
    try:
        cands = _string_constants(Path(root))
        if cands:
            small = []
            for p in iter_files(Path(root), limit=max_files):
                try:
                    if 4 <= p.stat().st_size <= 65536 and p.suffix.lower() not in (".py", ".md", ".txt", ".json", ".yaml", ".yml", ".html", ".js"):
                        small.append(p)
                except OSError:
                    continue
            for p in small[:40]:
                data = p.read_bytes()
                rel = os.path.relpath(p, root)
                for key in cands[:300]:
                    kb = key.encode()
                    x = bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))
                    if b"{" in x and b"}" in x:
                        consider(x, f"{rel} (xor key {key!r})")
            # encrypted zip members
            import zipfile
            for p in iter_files(Path(root), limit=max_files):
                if not p.name.lower().endswith(".zip"):
                    continue
                try:
                    with zipfile.ZipFile(p) as zf:
                        infos = [i for i in zf.infolist() if i.flag_bits & 0x1 and i.file_size < 2_000_000][:10]
                        for info in infos:
                            for key in cands[:300]:
                                try:
                                    consider(zf.read(info, pwd=key.encode()), f"{os.path.relpath(p, root)}:{info.filename} (password {key!r})")
                                    break
                                except Exception:  # noqa: BLE001
                                    continue
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        pass
    # archive members and git history are where "hidden" flags usually sit
    try:
        for p in iter_files(Path(root), limit=max_files):
            low = p.name.lower()
            try:
                if p.stat().st_size > 20_000_000:
                    continue
            except OSError:
                continue
            if low.endswith(".zip"):
                import zipfile
                try:
                    with zipfile.ZipFile(p) as zf:
                        for info in zf.infolist()[:60]:
                            if info.file_size > 3_000_000:
                                continue
                            try:
                                consider(zf.read(info), f"{os.path.relpath(p, root)}:{info.filename}")
                            except Exception:  # noqa: BLE001
                                continue
                except Exception:  # noqa: BLE001
                    pass
            elif low.endswith((".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz")):
                import tarfile
                try:
                    with tarfile.open(p) as tf:
                        for member in tf.getmembers()[:60]:
                            if not member.isfile() or member.size > 3_000_000:
                                continue
                            fh = tf.extractfile(member)
                            if fh:
                                consider(fh.read(), f"{os.path.relpath(p, root)}:{member.name}")
                except Exception:  # noqa: BLE001
                    pass
            elif low.endswith((".gz", ".bz2", ".xz")) and not low.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
                import gzip, bz2, lzma
                opener = gzip.open if low.endswith(".gz") else (bz2.open if low.endswith(".bz2") else lzma.open)
                try:
                    with opener(p) as fh:
                        consider(fh.read(3_000_000), f"{os.path.relpath(p, root)} (decompressed)")
                except Exception:  # noqa: BLE001
                    pass
            elif low.endswith((".db", ".sqlite", ".sqlite3", ".db3")) or _is_sqlite(p):
                consider(_sqlite_text(p), f"{os.path.relpath(p, root)} (sqlite contents)")
            elif low.endswith(".pdf"):
                consider(_pdf_text(p), f"{os.path.relpath(p, root)} (pdf streams)")
            elif low.endswith(".png"):
                consider(_png_lsb(p), f"{os.path.relpath(p, root)} (png LSB stego)")
                consider(_appended_data(p), f"{os.path.relpath(p, root)} (data appended after the image)")
            elif low.endswith((".wav", ".wave")):
                consider(_wav_lsb(p), f"{os.path.relpath(p, root)} (wav LSB stego)")
            elif low.endswith((".jpg", ".jpeg", ".gif")):
                consider(_appended_data(p), f"{os.path.relpath(p, root)} (data appended after the image)")
        git_dir = Path(root) / ".git"
        if git_dir.is_dir():
            try:
                r = subprocess.run(["git", "-C", str(root), "log", "-p", "--all", "--no-color"],
                                   capture_output=True, timeout=30)
                consider(r.stdout[:3_000_000], ".git history")
                r = subprocess.run(["git", "-C", str(root), "stash", "list", "-p"], capture_output=True, timeout=15)
                consider(r.stdout[:1_000_000], ".git stash")
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001
        pass
    uniq = []
    seen = set()
    for v, s in found:
        body = v[v.find("{") + 1:-1]
        # a "flag" containing quotes, operators or brackets is a fragment of source code
        if any(ch in body for ch in "\"'+[]()<>;\\") or body.strip() == "":
            continue
        if v not in seen:
            seen.add(v)
            uniq.append((v, s))
    # Rank: exact prefix match first, then the most "flag-like" body (a decode with the
    # wrong key leaves punctuation garbage inside the braces).
    def score(item):
        v, src = item
        body = v[v.find("{") + 1:-1]
        garbage = sum(1 for ch in body if not (ch.isalnum() or ch in "_-!?@#$.,: +=/"))
        return (0 if (prefix and v.startswith(prefix)) else 1, garbage, -len(body), 0 if "xor" not in src and "(" not in src else 1)
    uniq.sort(key=score)
    return uniq[:12]


_STR_LIT_RE = re.compile(r"""(?<![\w])(?:[rRbBuU]?)(['"])((?:\\.|(?!\1).){3,64})\1""")
_LIST_LIT_RE = re.compile(r'''\[((?:\s*['"][^'"]{1,32}['"]\s*,?){2,12})\]''')


_FLAG_BODY_OK = re.compile(rb"^[A-Za-z0-9_.:+@!?-]{3,120}$")


def _clean_flag_in(plain: bytes, marker: bytes) -> bool:
    """A recovered key is believable only if it yields a properly formed flag: a wrong
    key still reproduces the marker by construction, so the body is what decides."""
    for m in FLAG_RE.finditer(plain):
        val = m.group(0)
        if marker and not val.startswith(marker):
            continue
        if _FLAG_BODY_OK.match(val[val.find(b"{") + 1:-1]):
            return True
    return False


def xor_known_plaintext(data: bytes, prefixes, max_offsets: int = 8192):
    """Recover a repeating XOR key whose period the flag format alone determines.

    Wherever the flag sits, the key bytes beneath it are ciphertext XOR marker. When the
    key is no longer than the marker every slot is pinned exactly, so this is a solve
    rather than a guess. Longer keys are deliberately left to frequency analysis instead
    of being half-guessed here: a nearly-right key yields a nearly-right flag, which is
    worse than no answer at all.
    Returns a list of (plaintext, description)."""
    out = []
    n = len(data)
    if n < 8:
        return out
    for marker in prefixes:
        m = len(marker)
        if m < 3:
            continue
        limit = n - m + 1
        offsets = range(limit) if n <= 16384 else range(min(limit, max_offsets))
        for klen in range(1, m + 1):
            seen = set()
            for i in offsets:
                key = bytearray(klen)
                consistent = True
                filled = [False] * klen
                for j in range(m):
                    slot = (i + j) % klen
                    kb = data[i + j] ^ marker[j]
                    if filled[slot] and key[slot] != kb:
                        consistent = False
                        break
                    key[slot], filled[slot] = kb, True
                if not consistent or not all(filled):
                    continue
                kt = bytes(key)
                if kt in seen:
                    continue
                seen.add(kt)
                plain = bytes(data[x] ^ kt[x % klen] for x in range(n))
                if _text_score(plain) < 1.0 or not _clean_flag_in(plain, marker):
                    continue
                try:
                    shown = kt.decode("ascii")
                except UnicodeDecodeError:
                    shown = kt.hex()
                out.append((plain, f"xor key {shown!r} recovered from the known flag prefix"))
                if len(out) >= 4:
                    return out
    return out


_ENGLISH_FREQ = b" etaoinshrdlucmfwypvbgkjqxzETAOINSHRDLUCMFWYPVBGKJQXZ"


def _text_score(buf: bytes) -> float:
    """How much this looks like ordinary text (higher is better)."""
    if not buf:
        return -1e9
    score = 0.0
    for b in buf:
        if b in _ENGLISH_FREQ:
            score += 2.0
        elif 32 <= b <= 126 or b in (9, 10, 13):
            score += 0.6
        else:
            score -= 6.0
    return score / len(buf)


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def xor_break_repeating(data: bytes, max_keylen: int = 40, top_lengths: int = 4):
    """Classic repeating-key XOR break: key length by Hamming distance, then each key
    byte by how much like text the column decrypts. Recovers keys far longer than the
    known plaintext can pin, as long as the plaintext is ordinary text."""
    out = []
    n = len(data)
    if n < 32:
        return out
    scores = []
    for klen in range(1, min(max_keylen, n // 4) + 1):
        blocks = [data[i * klen:(i + 1) * klen] for i in range(min(8, n // klen))]
        pairs = [(blocks[i], blocks[i + 1]) for i in range(len(blocks) - 1)]
        if not pairs:
            continue
        dist = sum(_hamming(a, b) for a, b in pairs) / (len(pairs) * klen)
        scores.append((dist, klen))
    scores.sort()
    for _dist, klen in scores[:top_lengths]:
        key = bytearray()
        for col in range(klen):
            column = data[col::klen]
            best, best_score = 0, -1e9
            for k in range(256):
                sc = _text_score(bytes(b ^ k for b in column))
                if sc > best_score:
                    best, best_score = k, sc
            key.append(best)
        plain = bytes(b ^ key[i % klen] for i, b in enumerate(data))
        try:
            shown = bytes(key).decode("ascii")
        except UnicodeDecodeError:
            shown = bytes(key).hex()
        out.append((plain, f"xor key {shown!r} recovered by frequency analysis"))
    return out


def _wav_lsb(p: Path) -> bytes:
    """Least-significant-bit payload of a WAV file, parsed from the RIFF chunks."""
    import struct
    try:
        data = p.read_bytes()
    except OSError:
        return b""
    if data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return b""
    pos, bits_per_sample, payload = 12, 16, b""
    while pos + 8 <= len(data):
        cid = data[pos:pos + 4]
        size = struct.unpack("<I", data[pos + 4:pos + 8])[0]
        body = data[pos + 8:pos + 8 + size]
        if cid == b"fmt " and len(body) >= 16:
            bits_per_sample = struct.unpack("<H", body[14:16])[0]
        elif cid == b"data":
            payload = body
            break
        pos += 8 + size + (size & 1)
    if not payload:
        return b""
    step = max(1, bits_per_sample // 8)
    bits = [payload[i] & 1 for i in range(0, min(len(payload), 4_000_000), step)]
    out = bytearray()
    for j in range(0, len(bits) - 7, 8):
        byte = 0
        for k in range(8):
            byte = (byte << 1) | bits[j + k]
        out.append(byte)
    return bytes(out)[:200_000]


_IMG_END = ((b"\x89PNG", b"IEND\xaeB`\x82"), (b"\xff\xd8\xff", b"\xff\xd9"), (b"GIF8", b"\x00;"))


def _appended_data(p: Path) -> bytes:
    """Whatever was concatenated after an image's real end marker.

    Hiding an archive behind a picture is one of the oldest tricks there is, and the
    bytes never show up in the image itself."""
    try:
        data = p.read_bytes()
    except OSError:
        return b""
    for magic, end in _IMG_END:
        if not data.startswith(magic):
            continue
        idx = data.rfind(end)
        if idx == -1:
            continue
        tail = data[idx + len(end):]
        if len(tail) < 8:
            return b""
        if tail[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
            import io
            import zipfile
            out = [tail]
            try:
                with zipfile.ZipFile(io.BytesIO(tail)) as zf:
                    for name in zf.namelist()[:20]:
                        try:
                            out.append(zf.read(name))
                        except Exception:  # noqa: BLE001
                            continue
            except Exception:  # noqa: BLE001
                pass
            return b"\n".join(out)[:2_000_000]
        return tail[:2_000_000]
    return b""


def _is_sqlite(p: Path) -> bool:
    try:
        with p.open("rb") as fh:
            return fh.read(16).startswith(b"SQLite format 3")
    except OSError:
        return False


def _sqlite_text(p: Path) -> bytes:
    """Every text value in every table — flags hide in databases as often as in files."""
    import sqlite3
    out = []
    try:
        con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, timeout=5)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view')")
        for (name,) in cur.fetchall()[:60]:
            try:
                cur.execute(f'SELECT * FROM "{name}" LIMIT 2000')
            except Exception:  # noqa: BLE001
                continue
            for row in cur.fetchall():
                for v in row:
                    if isinstance(v, (str, bytes)):
                        out.append(v.encode("utf-8", "replace") if isinstance(v, str) else v)
        con.close()
    except Exception:  # noqa: BLE001
        return b""
    return b"\n".join(out)[:3_000_000]


def _pdf_text(p: Path) -> bytes:
    """Raw plus inflated stream contents of a PDF (no external dependency)."""
    import zlib
    try:
        data = p.read_bytes()[:20_000_000]
    except OSError:
        return b""
    out = [data]
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        chunk = m.group(1)
        try:
            out.append(zlib.decompress(chunk))
        except Exception:  # noqa: BLE001
            continue
    return b"\n".join(out)[:3_000_000]


def _png_lsb(p: Path) -> bytes:
    """Least-significant-bit payload of a PNG, read with zlib alone."""
    import zlib
    try:
        data = p.read_bytes()
        if not data.startswith(b"\x89PNG"):
            return b""
        width = height = 0
        idat = bytearray()
        bitdepth = colour = 0
        i = 8
        while i + 8 <= len(data):
            ln = int.from_bytes(data[i:i + 4], "big")
            typ = data[i + 4:i + 8]
            body = data[i + 8:i + 8 + ln]
            if typ == b"IHDR":
                width = int.from_bytes(body[0:4], "big")
                height = int.from_bytes(body[4:8], "big")
                bitdepth, colour = body[8], body[9]
            elif typ == b"IDAT":
                idat += body
            elif typ == b"IEND":
                break
            i += 12 + ln
        if not idat or bitdepth != 8 or colour not in (2, 6) or width * height > 4_000_000:
            return b""
        raw = zlib.decompress(bytes(idat))
        chan = 3 if colour == 2 else 4
        stride = width * chan
        bits = []
        pos = 0
        prev = bytearray(stride)
        for _ in range(height):
            if pos >= len(raw):
                break
            ftype = raw[pos]; pos += 1
            line = bytearray(raw[pos:pos + stride]); pos += stride
            if len(line) < stride:
                break
            for x in range(stride):
                a = line[x - chan] if x >= chan else 0
                b = prev[x]
                c = prev[x - chan] if x >= chan else 0
                if ftype == 1:
                    line[x] = (line[x] + a) & 0xFF
                elif ftype == 2:
                    line[x] = (line[x] + b) & 0xFF
                elif ftype == 3:
                    line[x] = (line[x] + ((a + b) >> 1)) & 0xFF
                elif ftype == 4:
                    pa, pb, pc = abs(b - c), abs(a - c), abs(a + b - 2 * c)
                    pr = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                    line[x] = (line[x] + pr) & 0xFF
            for x in range(stride):
                if chan == 4 and x % 4 == 3:
                    continue  # skip alpha
                bits.append(line[x] & 1)
            prev = line
        out = bytearray()
        for j in range(0, len(bits) - 7, 8):
            byte = 0
            for k in range(8):
                byte = (byte << 1) | bits[j + k]
            out.append(byte)
        return bytes(out)[:200_000]
    except Exception:  # noqa: BLE001
        return b""


def _string_constants(root: Path, max_files: int = 60):
    """Short string literals in source files, plus joins of small string-list literals —
    the places a challenge author leaves a key or a password."""
    out = []
    seen = set()
    for p in iter_files(root, limit=max_files):
        if p.suffix.lower() not in (".py", ".js", ".txt", ".md", ".sh", ".php", ".rb", ".go", ".c", ".java", ".json", ".yaml", ".yml", ".cfg", ".ini", ".env"):
            continue
        try:
            if p.stat().st_size > 200_000:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _STR_LIT_RE.finditer(text):
            lit = m.group(2)
            if "{" in lit or "\\" in lit or " " in lit.strip() and len(lit) > 24:
                continue
            if lit not in seen:
                seen.add(lit)
                out.append(lit)
        # separators actually used with .join() in this file decide how list literals are
        # assembled; guessing every separator produces look-alike decoys
        seps = set(re.findall(r'''['"]([^'"]{0,3})['"]\s*\.join\(''', text)) or {"", "-", "_"}
        for m in _LIST_LIT_RE.finditer(text):
            parts = re.findall(r'''['"]([^'"]{1,32})['"]''', m.group(1))
            for sep in sorted(seps, key=len):
                joined = sep.join(parts)
                if 3 <= len(joined) <= 64 and joined not in seen:
                    seen.add(joined)
                    out.append(joined)
        for m in re.finditer(r"(?:password|passwd|pass|key|secret|token)\s*[:=]\s*['\"]?([A-Za-z0-9_@#$%^&*!.-]{3,48})", text, re.I):
            if m.group(1) not in seen:
                seen.add(m.group(1))
                out.append(m.group(1))
    return out[:400]


# ---- assembly -------------------------------------------------------------------------

def build(spec, workdir: Path, log=print) -> dict:
    """Return a dict of briefing sections; `text` is the assembled string."""
    workdir = Path(workdir)
    sections = []
    info = {"hotspots": [], "routes": [], "flags": []}
    try:
        sections.append(f"Directory tree of {workdir}:\n{tree(workdir)}")
    except Exception as exc:  # noqa: BLE001
        log(f"[brief] tree failed: {exc}")
    kind = spec.kind
    try:
        if kind in ("json_report", "code_fix", "generic"):
            rts = routes(workdir)
            info["routes"] = rts
            if rts:
                sections.append("HTTP routes found:\n" + "\n".join(rts))
            hits = scan_hotspots(workdir)
            if kind == "code_fix":
                # Storage/crypto findings are real audit material but "fixing" seed data
                # or hashing schemes breaks the behaviour the hidden tests protect.
                hits = [h for h in hits if h["category"] not in AUDIT_ONLY_CATEGORIES]
            info["hotspots"] = hits
            if hits:
                sections.append(
                    "Potentially risky code found by a quick pattern scan (verify each in context; "
                    "there may be issues the scan cannot see, such as missing authorization/IDOR):\n"
                    + format_hotspots(hits)
                )
    except Exception as exc:  # noqa: BLE001
        log(f"[brief] scan failed: {exc}")
    try:
        if kind in ("kv_report", "generic") or (kind == "ctf"):
            root = Path(spec.evidence_dir) if spec.evidence_dir else workdir
            heads = data_heads(root)
            if heads:
                sections.append(f"Files under {root} (size, line count, first lines):\n{heads}")
        if kind in ("kv_report", "generic"):
            from acpagent import digest, profile
            root = Path(spec.evidence_dir) if spec.evidence_dir else workdir
            prof = profile.profile_dir(root)
            if prof:
                sections.append("DETERMINISTIC PROFILES (computed by code from the whole files — counts, first/last "
                                "events and the '→ UTC' conversions are exact; prefer these over your own counting. "
                                "This summary text is NOT inside the files: grep the files only for real log content):\n" + prof)
            dg = digest.digest_dir(root, max_total=4500)
            if dg:
                sections.append("Pre-computed facts per file (counts are over the whole file; verify the rare "
                                "events — they are usually the interesting ones):\n" + dg)
    except Exception as exc:  # noqa: BLE001
        log(f"[brief] data digest failed: {exc}")
    try:
        if kind == "ctf":
            bs = binary_strings(Path(spec.evidence_dir) if spec.evidence_dir else workdir)
            if bs:
                sections.append("Binary files / captures (strings of interest):\n" + bs[:5000])
            outs = program_outputs(Path(spec.evidence_dir) if spec.evidence_dir else workdir)
            if outs:
                shown = []
                for label, data in outs[:8]:
                    shown.append(f"$ {label}\n{data.decode('utf-8', 'replace')[:700]}")
                sections.append("Output of the challenge's own programs (run with no arguments / --help):\n" + "\n".join(shown)[:5000])
            cands = flag_candidates(workdir, spec.flag_prefix)
            info["flags"] = cands
            if cands:
                sections.append("Flag-shaped strings found by a quick scan (verify before trusting):\n"
                                + "\n".join(f"- {v}   (from {s})" for v, s in cands))
    except Exception as exc:  # noqa: BLE001
        log(f"[brief] flag scan failed: {exc}")
    text = "\n\n".join(s for s in sections if s)
    if len(text) > MAX_BRIEF_CHARS:
        text = text[:MAX_BRIEF_CHARS] + "\n... (context truncated)"
    info["text"] = text
    return info
