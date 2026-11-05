from datetime import timedelta

import jwt
import pytest

from app.core.security import create_access_token, decode_access_token, hash_password, verify_password
from app.services.ingest import make_fingerprint


def test_password_hash_roundtrip():
    h = hash_password("a-long-password-1")
    assert h != "a-long-password-1"
    assert verify_password("a-long-password-1", h)


def test_wrong_password_rejected():
    assert not verify_password("nope", hash_password("a-long-password-1"))


def test_token_roundtrip():
    claims = decode_access_token(create_access_token("alice", "admin"))
    assert claims["sub"] == "alice" and claims["role"] == "admin"


def test_expired_token_rejected():
    tok = create_access_token("alice", "admin", expires_delta=timedelta(seconds=-5))
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_access_token(tok)


def test_tampered_token_rejected():
    tok = create_access_token("alice", "viewer")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(tok[:-3] + "abc")


def test_alg_none_token_rejected():
    forged = jwt.encode({"sub": "alice", "exp": 9999999999}, key=None, algorithm="none")
    with pytest.raises(jwt.PyJWTError):
        decode_access_token(forged)


def test_fingerprint_is_stable_and_case_insensitive():
    assert make_fingerprint("Nessus", "HOST-1", "P1") == make_fingerprint("nessus ", "host-1", "p1")


def test_fingerprint_differs_per_asset():
    assert make_fingerprint("nessus", "a", "P1") != make_fingerprint("nessus", "b", "P1")
