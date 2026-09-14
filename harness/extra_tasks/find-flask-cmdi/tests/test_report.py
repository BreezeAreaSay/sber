import json
from pathlib import Path
P = Path("/app/security_report.json")
def _flat(v):
    if isinstance(v, dict): return " ".join(_flat(x) for x in v.values())
    if isinstance(v, list): return " ".join(_flat(x) for x in v)
    return str(v)
def _load():
    d = json.loads(P.read_text()); assert isinstance(d, dict) and isinstance(d.get("findings"), list) and d["findings"]; return d["findings"]
def test_exists(): assert P.exists()
def test_cmdi():
    fs = _load()
    ok = [f for f in fs if any(s in _flat(f).lower() for s in ("command injection", "os command", "shell injection", "cwe-78", "shell=true", "subprocess", "arbitrary command"))
          and any(s in _flat(f).lower() for s in ("ping", "/ping", "host"))]
    assert ok, "no command-injection finding for /ping"
def test_traversal():
    fs = _load()
    ok = [f for f in fs if any(s in _flat(f).lower() for s in ("path traversal", "directory traversal", "cwe-22", "../", "arbitrary file"))
          and any(s in _flat(f).lower() for s in ("download", "/download", "file"))]
    assert ok, "no path-traversal finding for /download"
