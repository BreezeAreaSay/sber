def test_healthz(client):
    assert client.get("/healthz").json()["status"] == "ok"

def test_ping_localhost(client):
    r = client.get("/ping", params={"host": "127.0.0.1"})
    assert r.status_code == 200
    assert r.json()["host"] == "127.0.0.1"

def test_download_readme(client):
    r = client.get("/download", params={"file": "readme.txt"})
    assert r.status_code == 200
    assert "hello from readme" in r.text

def test_files_list(client):
    assert "readme.txt" in client.get("/files").json()["files"]
