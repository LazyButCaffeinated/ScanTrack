from tests.conftest import sample_payload


def test_ingest_creates_findings(client, auth):
    r = client.post("/api/v1/ingest", json=sample_payload(3), headers=auth("analyst"))
    assert r.status_code == 200
    assert r.json() == {"received": 3, "created": 3, "updated": 0, "reopened": 0}


def test_reingest_deduplicates(client, auth):
    h = auth("analyst")
    client.post("/api/v1/ingest", json=sample_payload(3), headers=h)
    r = client.post("/api/v1/ingest", json=sample_payload(3), headers=h)
    assert r.json()["created"] == 0 and r.json()["updated"] == 3
    assert client.get("/api/v1/findings", headers=h).json()["total"] == 3


def test_duplicates_inside_one_payload_collapse(client, auth):
    p = sample_payload(1)
    p["findings"] *= 3
    r = client.post("/api/v1/ingest", json=p, headers=auth("analyst"))
    assert r.json()["created"] == 1


def test_fixed_finding_reopens_when_seen_again(client, auth):
    h = auth("analyst")
    client.post("/api/v1/ingest", json=sample_payload(1), headers=h)
    client.patch("/api/v1/findings/1/status", json={"status": "fixed"}, headers=h)
    r = client.post("/api/v1/ingest", json=sample_payload(1), headers=h)
    assert r.json()["reopened"] == 1
    assert client.get("/api/v1/findings/1", headers=h).json()["status"] == "open"


def test_viewer_cannot_ingest(client, auth):
    assert client.post("/api/v1/ingest", json=sample_payload(1), headers=auth("viewer")).status_code == 403


def test_invalid_severity_422(client, auth):
    p = sample_payload(1)
    p["findings"][0]["severity"] = "apocalyptic"
    assert client.post("/api/v1/ingest", json=p, headers=auth("analyst")).status_code == 422


def test_oversized_payload_422(client, auth):
    p = sample_payload(1)
    p["findings"] = p["findings"] * 5001
    assert client.post("/api/v1/ingest", json=p, headers=auth("analyst")).status_code == 422


def test_sql_injection_string_stored_as_plain_data(client, auth):
    p = sample_payload(1)
    p["findings"][0]["title"] = "'; DROP TABLE findings; --"
    h = auth("analyst")
    client.post("/api/v1/ingest", json=p, headers=h)
    r = client.get("/api/v1/findings/1", headers=h)
    assert r.json()["title"] == "'; DROP TABLE findings; --"
