from tests.conftest import sample_payload


def seed(client, h, n=10):
    client.post("/api/v1/ingest", json=sample_payload(n), headers=h)


def test_list_pagination(client, auth):
    h = auth("analyst")
    seed(client, h, 10)
    r = client.get("/api/v1/findings", params={"limit": 4, "offset": 8}, headers=h).json()
    assert r["total"] == 10 and len(r["items"]) == 2


def test_limit_is_capped(client, auth):
    assert client.get("/api/v1/findings", params={"limit": 9999}, headers=auth("viewer")).status_code == 422


def test_filter_by_severity(client, auth):
    h = auth("analyst")
    seed(client, h, 10)
    r = client.get("/api/v1/findings", params={"severity": "critical"}, headers=h).json()
    assert r["total"] == 2 and all(i["severity"] == "critical" for i in r["items"])


def test_filter_by_status(client, auth):
    h = auth("analyst")
    seed(client, h, 3)
    client.patch("/api/v1/findings/1/status", json={"status": "fixed"}, headers=h)
    assert client.get("/api/v1/findings", params={"status": "fixed"}, headers=h).json()["total"] == 1


def test_filter_by_asset(client, auth):
    h = auth("analyst")
    seed(client, h, 5)
    assert client.get("/api/v1/findings", params={"asset": "HOST-2.lab"}, headers=h).json()["total"] == 1


def test_get_one_and_404(client, auth):
    h = auth("viewer")
    assert client.get("/api/v1/findings/999", headers=h).status_code == 404


def test_open_to_fixed_sets_fixed_at(client, auth):
    h = auth("analyst")
    seed(client, h, 1)
    r = client.patch("/api/v1/findings/1/status", json={"status": "fixed"}, headers=h).json()
    assert r["status"] == "fixed" and r["fixed_at"] is not None


def test_invalid_transition_409(client, auth):
    h = auth("analyst")
    seed(client, h, 1)
    client.patch("/api/v1/findings/1/status", json={"status": "fixed"}, headers=h)
    r = client.patch("/api/v1/findings/1/status", json={"status": "in_progress"}, headers=h)
    assert r.status_code == 409


def test_viewer_cannot_change_status(client, auth, make_user):
    seed(client, auth("analyst"), 1)
    h = auth("viewer")
    assert client.patch("/api/v1/findings/1/status", json={"status": "fixed"}, headers=h).status_code == 403


def test_viewer_can_read(client, auth):
    seed(client, auth("analyst"), 2)
    assert client.get("/api/v1/findings", headers=auth("viewer")).status_code == 200
