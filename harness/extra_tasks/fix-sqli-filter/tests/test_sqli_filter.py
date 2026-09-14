def test_status_filter_injection_does_not_widen_results(client):
    r = client.get("/items", params={"status": "open' OR '1'='1"})
    assert r.status_code in (200, 400, 422), r.text
    if r.status_code == 200:
        assert all(i["status"] == "open' OR '1'='1" for i in r.json()) or r.json() == [], "injection widened the filter"

def test_status_filter_union_does_not_leak(client):
    payload = "x' UNION SELECT 1, username, password, 'open', 'high', 1, now(), now() FROM users --"
    r = client.get("/items", params={"status": payload})
    assert "secret123" not in r.text and "pass-alice" not in r.text
