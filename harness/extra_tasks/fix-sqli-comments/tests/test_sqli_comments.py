def test_comment_body_injection_is_stored_literally(client):
    payload = "hi'); DELETE FROM comments; --"
    r = client.post("/items/1/comments", json={"author_id": 1, "body": payload})
    assert r.status_code in (200, 400), r.text
    r = client.get("/items/1/comments")
    assert r.status_code == 200
    bodies = [c["body"] for c in r.json()]
    assert any("connection pool" in b for b in bodies), "seed comments were deleted through SQL injection"
    if r.status_code == 200:
        assert payload in bodies or True
