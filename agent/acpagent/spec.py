"""Deterministic reading of the task statement.

Classification only chooses the prompt, the completion oracle and the fallback
artifact. It never decides the answer, so a wrong guess costs a little context, not
the task.
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

_ABS_PATH_RE = re.compile(r"(?<![\w./-])(/(?:[\w.+-]+/)*[\w.+-]+)")
_BACKTICK_REL_RE = re.compile(r"`([\w][\w./+-]*\.[A-Za-z0-9]{1,6})`")
_WRITE_VERB_RE = re.compile(
    r"\b(writ\w*|sav\w*|creat\w*|record\w*|stor\w*|plac\w*|put|output\w*|emit\w*|report|"
    r"deliverable|produc\w*|generat\w*|export\w*|dump\w*|submit\w*|answer|result)\b|"
    r"запи\w*|сохран\w*|созда\w*|помест\w*|вывед\w*|выгруз\w*|сформир\w*|отч[её]т\w*|ответ\w*|результат\w*|файл\w*",
    re.I,
)
_VERB_WINDOW = 110

_EXACT_CONTENT_RES = (
    re.compile(r"content(?:s)? (?:is|are|must be) exactly (?:the single word |the word |the string |the text )?`([^`\n]+)`", re.I),
    re.compile(r"exact content `([^`\n]+)`", re.I),
    re.compile(r"contain(?:s|ing)? exactly (?:the single word |the word |the string |the text )?`([^`\n]+)`", re.I),
    re.compile(r"whose (?:entire )?content(?:s)? (?:is|are) exactly `([^`\n]+)`", re.I),
    re.compile(r"with (?:the )?(?:exact )?content `([^`\n]+)`", re.I),
    re.compile(r"containing (?:only |just )?(?:the (?:single )?(?:word|string|text|line) )?`([^`\n]+)`", re.I),
    re.compile(r"(?:содержим\w+|содержан\w+|текст\w*)[^`\n]{0,60}?(?:ровно|точно|в точности|только)[^`\n]{0,30}?`([^`\n]+)`", re.I),
    re.compile(r"(?:ровно|точно|в точности)\s+(?:одно слово |слово |строк[ау] |текст )?`([^`\n]+)`", re.I),
)

_KEY_BULLET_RE = re.compile(r"^\s*[-*]\s*`?([a-z][a-z0-9_]{1,40})`?\s*(?:[:—-].*)?$", re.M)
_KEY_INLINE_RE = re.compile(r"`([a-z][a-z0-9_]{1,40})`\s*=")
_KV_SHAPE_RE = re.compile(
    r"key\s*=\s*value|`[a-z_][a-z0-9_]*`\s*=|one .{0,20}per line|per line|the following keys|these keys|"
    r"with (?:the )?(?:keys|fields)|\bkeys\s*:|(?:exactly )?(?:\d+|two|three|four|five|six|seven|eight)\s+(?:non-empty\s+)?lines|"
    r"ключ\s*=\s*значение|(?:по одной|одна|одну) (?:пар[аеуы]|строк[аеиу]) на строк|(?:ровно|точно) (?:\d+|две|три|четыре|пять|шесть) (?:непуст\w+ )?строк|следующие ключи|эти ключи|ключ[аи]?:",
    re.I,
)
_KEY_STOPWORDS = frozenset({
    "key", "value", "true", "false", "null", "none", "severity", "evidence", "cwe", "cve",
    "remediation", "recommendation", "impact", "poc", "vulnerability", "vulnerabilities",
    "mitigation", "references", "finding", "findings", "title", "description", "category",
    "location", "json", "txt", "utf", "md", "py", "app", "tests", "test",
})

_CTF_STRONG_RE = re.compile(
    r"\bctf\b|capture[- ]the[- ]flag|\bflag\b.{0,40}\{|\{[^{}\s]{2,60}\}.{0,40}\bflag\b|флаг\w*|"
    r"(?:recover|retrieve|reveal|extract|obtain|print|find|read|get|decode|decrypt|capture|submit|write)\s+(?:the\s+|a\s+)?flag\b|"
    r"the flag is|flag\.txt|\bflag format\b|\bthe flag\b",
    re.I,
)
_FORENSICS_RE = re.compile(
    r"forensic|incident|exfil|\bIR-\d|correlat|attribut|log analysis|triage the logs|"
    r"compromis\w+ (?:user|account|host)|attacker|\bpcap\b|memory dump|timeline|malware|"
    r"\bsiem\b|\bsoc\b|analyst|форензик\w*|инцидент\w*|расследован\w*|злоумышленник\w*|атакующ\w*|"
    r"скомпрометирован\w*|утечк\w*|эксфильтрац\w*|журнал\w*|\bлог[иа]?\b|логов\b|логах\b",
    re.I,
)
_REPORT_RE = re.compile(
    r"security[_ ]report|\bfindings\b|bug bounty|security audit|audit report|report the vulnerab|"
    r"machine-readable|json report|vulnerability report|pentest report|assessment report|"
    r"отч[её]т\w* (?:о|об|по) (?:уязвим|безопас|аудит)|аудит\w* безопасност\w*|bug ?bounty|найденн\w+ уязвим\w*|json-отч[её]т",
    re.I,
)
_FIX_RE = re.compile(
    r"\b(?:fix|fixes|fixed|fixing|patch|patches|patched|patching|remediat\w+|harden\w*|"
    r"secure|secures|secured|securing|repair\w*|mitigat\w+|resolve\w*|eliminate\w*|close the)\b|"
    r"исправ\w*|почин\w*|устран\w*|закр\w+ уязвим\w*|пропатч\w*|защити\w*",
    re.I,
)
_NO_MODIFY_RE = re.compile(
    r"do not (?:modify|change|edit|alter|touch)|don't (?:modify|change|edit)|without (?:modifying|changing)|must not (?:modify|change)|read-only|"
    r"не (?:изменя\w*|модифицир\w*|редактир\w*|прав\w*|меня\w*) (?:код|исходн\w*|файл\w*|приложен\w*)",
    re.I,
)
_CODE_RE = re.compile(
    r"\bpytest\b|\btests?/|\btest suite\b|source code|codebase|application|endpoint|module|repository|"
    r"vulnerab\w+|security (?:issue|defect|bug|flaw)|pyproject|package\.json|requirements\.txt|"
    r"\.(?:py|js|ts|jsx|tsx|go|php|rb|java|cs|rs|c|cc|cpp|h)\b|\bcode\b|function|route|handler|"
    r"controller|middleware|service|login|authentication|\bauth\b|\bquery\b|injection|"
    r"уязвим\w*|\bкод\w*|приложен\w*|тест\w*|инъекц\w*|функци\w*|обработчик\w*|эндпоинт\w*",
    re.I,
)
_TEST_CMD_RE = re.compile(
    r"`([^`\n]*(?:pytest|npm test|yarn test|pnpm test|go test|cargo test|make test|mvn test|gradle test|"
    r"php artisan test|phpunit|rspec|bundle exec|python -m unittest|python3 -m unittest|unittest|jest|mocha|"
    r"tox|nox|\bbats\b|dotnet test)[^`\n]*)`",
    re.I,
)
_FLAG_FORMAT_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9_]{1,15})\{[^{}\n]{0,80}\}")

DEFAULT_REPORT_FIELDS = ["title", "severity", "category", "location", "evidence", "impact", "recommendation"]


@dataclass
class Spec:
    kind: str = "generic"                # exact | kv_report | json_report | ctf | code_fix | generic
    deliverable: str = ""                # absolute path of the graded file, if the task names one
    exact_content: str = None
    exact_files: list = field(default_factory=list) # [(path, content)] for multi-file exact tasks
    keys: list = field(default_factory=list)        # kv_report keys, in statement order
    json_fields: list = field(default_factory=list) # per-finding fields for a json report
    json_root: str = "findings"
    report_format: str = "json"           # json | text (markdown/plain report)
    test_cmd: str = ""
    no_modify: bool = False
    evidence_dir: str = ""
    flag_prefix: str = ""
    stdout_answer: bool = False          # task asks for the answer in the reply rather than a file
    also_fix: bool = False

    def describe(self) -> str:
        return (f"kind={self.kind} deliverable={self.deliverable or '-'} keys={self.keys or '-'} "
                f"tests={self.test_cmd or '-'} no_modify={self.no_modify} evidence={self.evidence_dir or '-'}")


# ---- helpers -------------------------------------------------------------------------

def _abs_paths(text: str):
    out = []
    for m in _ABS_PATH_RE.finditer(text):
        p = m.group(1).rstrip(".,;:)")
        if p in ("/", "/app") or len(p) < 3:
            continue
        # a bare directory such as /app/incident/ is an input, not a deliverable
        out.append((m.start(), p))
    return out


def _near_write_verb(text: str, pos: int) -> bool:
    return bool(_WRITE_VERB_RE.search(text[max(0, pos - _VERB_WINDOW):pos]))


def find_deliverable(text: str, workdir: Path, *preferred) -> str:
    """The path the instruction tells you to *write* — rarely the first it mentions."""
    for name in preferred:
        m = re.search(rf"(/[\w./+-]*{re.escape(name)})", text)
        if m:
            return m.group(1)
    paths = _abs_paths(text)
    file_like = [(pos, p) for pos, p in paths if "." in p.rsplit("/", 1)[-1] and not text[text.find(p) + len(p):][:1] == "/"]
    written = [(pos, p) for pos, p in file_like if _near_write_verb(text, pos)]
    if written:
        return written[-1][1]
    if file_like:
        # prefer well-known deliverable names
        for pos, p in file_like:
            base = p.rsplit("/", 1)[-1].lower()
            if any(k in base for k in ("report", "answer", "flag", "result", "output", "solution", "findings")):
                return p
        return file_like[-1][1]
    rel = [(m.start(), m.group(1)) for m in _BACKTICK_REL_RE.finditer(text)]
    rel_written = [(pos, p) for pos, p in rel if _near_write_verb(text, pos)]
    if rel_written:
        p = rel_written[-1][1]
        return str(Path(workdir) / p)
    return ""


def find_evidence_dir(text: str, workdir: Path) -> str:
    for m in re.finditer(r"`(/[\w./+-]+/?)`", text):
        raw = m.group(1)
        last = raw.rstrip("/").rsplit("/", 1)[-1]
        if raw.endswith("/") or ("." not in last):
            p = raw.rstrip("/")
            if p and p != "/app" and Path(p).is_dir():
                return p
    for m in re.finditer(r"(?:under|in|inside|within|from)\s+`?(/[\w./+-]+?)/?`?[\s,.]", text):
        p = m.group(1)
        if p != "/app" and Path(p).is_dir():
            return p
    return ""


_FENCED_CONTENT_RE = re.compile(
    r"(?:with|containing|содержащ\w*|со следующим|с таким|с содержимым)\s+(?:(?:exactly|precisely|the following|this|следующ\w+|таким|точно|ровно)\s+)*"
    r"(?:content|contents|text|содержим\w+|текст\w*)\s*:?\s*\n```[a-zA-Z0-9_-]*\n(.*?)```",
    re.I | re.S,
)


def extract_exact_all(text: str):
    """Every (path, exact content) pair the statement pins down, in order."""
    matches = []
    for cm in _FENCED_CONTENT_RE.finditer(text):
        matches.append((cm.start(), cm.group(1)))
    for rx in _EXACT_CONTENT_RES:
        for cm in rx.finditer(text):
            matches.append((cm.start(), cm.group(1)))
    matches.sort()
    paths = _abs_paths(text)
    rel = [(m.start(), m.group(1)) for m in _BACKTICK_REL_RE.finditer(text)]
    out = []
    used = set()
    for pos, content in matches:
        before = [p for ppos, p in paths if ppos < pos and p not in used and "." in p.rsplit("/", 1)[-1]]
        chosen = before[-1] if before else ""
        if not chosen:
            rb = [p for ppos, p in rel if ppos < pos and p not in used]
            chosen = rb[-1] if rb else ""
        if not chosen:
            continue
        used.add(chosen)
        out.append((chosen, content))
    return out


def extract_exact(text: str):
    pairs = extract_exact_all(text)
    return pairs[0] if pairs else None


def extract_keys(text: str) -> list:
    if not _KV_SHAPE_RE.search(text) and len(_KEY_BULLET_RE.findall(text)) < 3:
        return []
    keys = _KEY_INLINE_RE.findall(text)
    if len(keys) < 2:
        keys = _KEY_BULLET_RE.findall(text)
    if len(keys) < 2:
        keys = re.findall(r"[-*]\s*`([a-z][a-z0-9_]{1,40})`", text)
    seen, ordered = set(), []
    for k in keys:
        if k not in seen and k not in _KEY_STOPWORDS:
            seen.add(k)
            ordered.append(k)
    return ordered if 2 <= len(ordered) <= 16 else []


def extract_json_fields(text: str):
    """Field names of one finding, read from the JSON example in the statement."""
    root = "findings"
    fields = []
    for m in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S):
        blob = m.group(1)
        cleaned = re.sub(r"//[^\n]*", "", blob)
        cleaned = re.sub(r",\s*([}\]])", r"\1", cleaned)
        cleaned = cleaned.replace("...", "")
        try:
            data = json.loads(cleaned)
        except ValueError:
            names = re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', blob)
            if names:
                if names[0] in ("findings", "vulnerabilities", "issues", "results", "report"):
                    root = names[0]
                    names = names[1:]
                fields = [n for n in dict.fromkeys(names) if n != root]
            continue
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(v, list) and v and isinstance(v[0], dict):
                    root = k
                    fields = list(v[0].keys())
                    break
            if not fields and all(not isinstance(v, (list, dict)) for v in data.values()):
                fields = list(data.keys())
        if fields:
            break
    return root, fields


def extract_test_cmd(text: str, workdir: Path) -> str:
    m = _TEST_CMD_RE.search(text)
    if m:
        cmd = m.group(1).strip()
        cmd = re.sub(r"^\$\s*", "", cmd)
        return cmd
    wd = Path(workdir)
    if (wd / "tests").is_dir() or (wd / "test").is_dir() or list(wd.glob("test_*.py")):
        return "python -m pytest -q -x --no-header -p no:cacheprovider"
    if (wd / "package.json").is_file():
        return "npm test --silent"
    if (wd / "go.mod").is_file():
        return "go test ./..."
    return ""


def flag_prefix(text: str) -> str:
    for m in _FLAG_FORMAT_RE.finditer(text):
        tag = m.group(1)
        if tag.lower() not in ("http", "https", "e", "eg"):
            return tag + "{"
    return ""


# ---- classification -------------------------------------------------------------------

def triage(instruction: str, workdir: Path) -> Spec:
    text = instruction or ""
    spec = Spec()
    spec.no_modify = bool(_NO_MODIFY_RE.search(text))
    spec.evidence_dir = find_evidence_dir(text, workdir)
    spec.flag_prefix = flag_prefix(text)

    exact_all = extract_exact_all(text)
    if exact_all:
        spec.kind = "exact"
        spec.exact_files = [(_absolute(pth, workdir), content) for pth, content in exact_all]
        spec.deliverable, spec.exact_content = spec.exact_files[0]
        return spec

    keys = extract_keys(text)
    forensics_hit = bool(_FORENSICS_RE.search(text))
    report_hit = bool(_REPORT_RE.search(text)) or ("json" in text.lower() and "report" in text.lower())
    ctf_hit = bool(_CTF_STRONG_RE.search(text))
    fix_hit = bool(_FIX_RE.search(text)) and bool(_CODE_RE.search(text)) and not spec.no_modify

    if keys and (forensics_hit or not report_hit):
        spec.kind = "kv_report"
        spec.keys = keys
        spec.deliverable = _absolute(find_deliverable(text, workdir, "incident_report.txt", "report.txt", "answer.txt"), workdir)
        return spec

    if report_hit and not (ctf_hit and "findings" not in text.lower()):
        spec.kind = "json_report"
        spec.json_root, spec.json_fields = extract_json_fields(text)
        if not spec.json_fields:
            spec.json_fields = list(DEFAULT_REPORT_FIELDS)
        spec.deliverable = _absolute(find_deliverable(text, workdir, "security_report.json", "report.json", "findings.json"), workdir)
        if not spec.deliverable:
            spec.deliverable = str(Path(workdir) / ("security_report.md" if ("markdown" in text.lower() or ".md" in text) and "json" not in text.lower() else "security_report.json"))
        ext = Path(spec.deliverable).suffix.lower()
        if ext in (".md", ".txt", ".rst", ".html") and "json" not in text.lower():
            spec.report_format = "text"
        spec.also_fix = fix_hit
        return spec

    if ctf_hit:
        spec.kind = "ctf"
        spec.deliverable = _absolute(find_deliverable(text, workdir, "flag.txt", "answer.txt", "solution.txt"), workdir)
        spec.stdout_answer = not spec.deliverable
        return spec

    if fix_hit:
        spec.kind = "code_fix"
        spec.test_cmd = extract_test_cmd(text, workdir)
        # A fix task may also demand a written artefact (notes, a patch file, a summary).
        path = find_deliverable(text, workdir)
        spec.deliverable = _absolute(path, workdir) if path and _near_write_verb(text, text.find(path.rsplit("/", 1)[-1])) else ""
        return spec

    if forensics_hit and keys:
        spec.kind = "kv_report"
        spec.keys = keys
        spec.deliverable = _absolute(find_deliverable(text, workdir), workdir)
        return spec

    spec.kind = "generic"
    spec.deliverable = _absolute(find_deliverable(text, workdir), workdir)
    spec.test_cmd = ""
    if not spec.deliverable:
        spec.stdout_answer = True
    return spec


def _absolute(path: str, workdir: Path) -> str:
    if not path:
        return ""
    p = Path(path)
    if not p.is_absolute():
        p = Path(workdir) / p
    return str(p)
