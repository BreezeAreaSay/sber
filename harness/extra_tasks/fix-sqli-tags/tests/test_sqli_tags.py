def test_tag_insert_injection_does_not_execute(client):
    # a stacked/terminated payload must be stored literally (or rejected), never executed
    payload = "zz'); DELETE FROM item_tags WHERE 1=1; --"
    r = client.post("/tags", json={"name": payload})
    assert r.status_code in (200, 400), r.text
    r = client.get("/items/1")
    assert r.status_code == 200
    r = client.get("/items", params={"tag": "bug"})
    assert r.status_code == 200
    assert r.json(), "item_tags rows were deleted through SQL injection"
    r = client.get("/tags")
    names = [t["name"] for t in r.json()]
    assert "zz" not in names
