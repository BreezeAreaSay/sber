def test_cmdi_blocked(client):
    r = client.get("/ping", params={"host": "127.0.0.1; id"})
    assert "uid=" not in r.text, f"command injection still works: {r.text}"
    r = client.get("/ping", params={"host": "$(id)"})
    assert "uid=" not in r.text
    r = client.get("/ping", params={"host": "127.0.0.1 && cat /etc/passwd"})
    assert "root:" not in r.text

def test_traversal_blocked(client):
    r = client.get("/download", params={"file": "../../../etc/passwd"})
    assert r.status_code in (400, 403, 404) or "root:" not in r.text
    r = client.get("/download", params={"file": "../app.py"})
    assert r.status_code in (400, 403, 404) or "Flask" not in r.text
