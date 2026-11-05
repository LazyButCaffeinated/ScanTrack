from tests.conftest import PASSWORD


def login(client, user, pw=PASSWORD):
    return client.post("/api/v1/auth/login", data={"username": user, "password": pw})


def test_login_success(client, make_user):
    make_user("bob", "viewer")
    r = login(client, "bob")
    assert r.status_code == 200 and r.json()["token_type"] == "bearer"


def test_login_wrong_password(client, make_user):
    make_user("bob", "viewer")
    assert login(client, "bob", "wrong-password-123").status_code == 401


def test_login_unknown_user_same_error_as_wrong_password(client, make_user):
    make_user("bob", "viewer")
    a = login(client, "bob", "wrong-password-123")
    b = login(client, "ghost")
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()  # no user enumeration


def test_inactive_user_cannot_login(client, make_user):
    make_user("old", "viewer", active=False)
    assert login(client, "old").status_code == 401


def test_protected_route_requires_token(client):
    assert client.get("/api/v1/findings").status_code == 401


def test_garbage_token_rejected(client):
    r = client.get("/api/v1/findings", headers={"Authorization": "Bearer not.a.token"})
    assert r.status_code == 401


def test_me_returns_current_user(client, auth):
    r = client.get("/api/v1/auth/me", headers=auth("analyst"))
    assert r.json()["username"] == "analyst"
    assert "hashed_password" not in r.json()


def test_viewer_cannot_create_user(client, auth):
    r = client.post("/api/v1/users", json={"username": "x" * 5, "password": "a-long-password-1"}, headers=auth("viewer"))
    assert r.status_code == 403


def test_admin_can_create_user(client, auth):
    r = client.post("/api/v1/users", json={"username": "newbie", "password": "a-long-password-1", "role": "analyst"}, headers=auth("admin"))
    assert r.status_code == 201 and r.json()["role"] == "analyst"


def test_duplicate_username_409(client, auth):
    h = auth("admin")
    body = {"username": "dupe", "password": "a-long-password-1"}
    client.post("/api/v1/users", json=body, headers=h)
    assert client.post("/api/v1/users", json=body, headers=h).status_code == 409


def test_weak_password_rejected(client, auth):
    r = client.post("/api/v1/users", json={"username": "weak", "password": "short"}, headers=auth("admin"))
    assert r.status_code == 422


def test_security_headers_present(client):
    r = client.get("/health")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
