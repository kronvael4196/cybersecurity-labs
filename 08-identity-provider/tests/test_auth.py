import importlib.util
from pathlib import Path
import secrets
import time
from unittest.mock import Mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
import httpx
import jwt
import pytest

from auth_server import create_app, hash_password
import middleware


@pytest.fixture
def identity(tmp_path):
    password = secrets.token_urlsafe(24)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "signing.key"
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    settings = {"IDP_KEY_PATH": str(path), "IDP_DB": str(tmp_path / "revocations.sqlite3"),
                "IDP_PASSWORD_HASH": hash_password(password), "IDP_ADMIN_TOKEN": secrets.token_urlsafe(32)}
    return TestClient(create_app(settings)), settings, password


def login(identity, scope="pki:read"):
    return identity[0].post("/login", data={"username": "analyst", "password": identity[2], "scope": scope})


def test_issue_and_verify_required_scopes(identity):
    response = login(identity)
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    token = response.json()["access_token"]
    claims = identity[0].get("/verify?scope=pki:read", headers={"Authorization": "Bearer " + token}).json()["claims"]
    assert claims["sub"] == "analyst" and claims["scope"] == "pki:read"
    assert identity[0].get("/verify?scope=pki:sign", headers={"Authorization": "Bearer " + token}).status_code == 403


def test_missing_auth_bad_password_and_scope_escalation(identity):
    assert identity[0].get("/verify").status_code == 401
    assert identity[0].get("/verify", headers={"Authorization": "Basic bogus"}).status_code == 401
    assert identity[0].post("/login", data={"username": "analyst", "password": secrets.token_hex(16)}).status_code == 401
    assert login(identity, "admin:all").status_code == 403


@pytest.mark.parametrize("case", ["expired", "audience", "issuer", "signature", "missing-exp"])
def test_reject_invalid_jwt(identity, case):
    now = int(time.time())
    claims = {"sub": "analyst", "iss": "cybersecurity-labs", "aud": "lab-services", "iat": now - 60,
              "nbf": now - 60, "exp": now + 60, "jti": "test-id", "scope": "pki:read"}
    key = Path(identity[1]["IDP_KEY_PATH"]).read_bytes()
    if case == "expired":
        claims["exp"] = now - 1
    elif case == "missing-exp":
        del claims["exp"]
    elif case == "audience":
        claims["aud"] = "another-service"
    elif case == "issuer":
        claims["iss"] = "another-issuer"
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(claims, key, algorithm="RS256")
    assert identity[0].get("/verify", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_revocation_persists_after_restart(identity):
    token = login(identity).json()["access_token"]
    header = {"Authorization": "Bearer " + token}
    jti = identity[0].get("/verify", headers=header).json()["claims"]["jti"]
    assert identity[0].post("/revoke", json={"jti": jti}, headers=header).status_code == 401
    assert identity[0].post("/revoke", json={"jti": jti}, headers={"Authorization": "Bearer " + identity[1]["IDP_ADMIN_TOKEN"]}).status_code == 200
    restarted = TestClient(create_app(identity[1]))
    assert restarted.get("/verify", headers=header).status_code == 401


def test_middleware_requires_bearer_and_fails_closed(monkeypatch):
    app = FastAPI()
    @app.get("/protected", dependencies=[Depends(middleware.require_scopes("http://identity:8001", "pki:read"))])
    def route():
        return {"ok": True}
    client = TestClient(app)
    assert client.get("/protected").status_code == 401
    monkeypatch.setattr(httpx.Client, "get", Mock(side_effect=httpx.ConnectError("offline")))
    # Use a different TestClient transport call because .get was mocked globally.
    assert client.request("GET", "/protected", headers={"Authorization": "Bearer arbitrary"}).status_code == 503


def test_rate_limit(identity):
    for _ in range(10):
        assert identity[0].post("/login", data={"username": "nobody", "password": ""}).status_code in (401, 422)
    # Real non-empty wrong credentials count toward the rate limit.
    statuses = [identity[0].post("/login", data={"username": "nobody", "password": secrets.token_hex(8)}).status_code for _ in range(11)]
    assert statuses[-1] == 429
