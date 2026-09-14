def test_user_by_name_works(client):
    r = client.get("/users/by-name/alice")
    assert r.status_code == 200 and r.json()["username"] == "alice"

def test_user_by_name_injection_blocked(client):
    r = client.get("/users/by-name/nobody' OR '1'='1")
    assert r.status_code == 404, f"injection returned a user: {r.text}"
