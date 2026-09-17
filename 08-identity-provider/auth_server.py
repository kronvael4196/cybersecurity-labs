"""Educational password-token service; not a full OAuth2/OIDC authorization server."""
from collections import defaultdict, deque
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time

from cryptography.hazmat.primitives import serialization
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordRequestForm
import jwt
from pydantic import BaseModel, Field


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 600_000).hex()
    return salt + ":" + digest


def create_app(settings=None):
    config = dict(os.environ)
    config.update(settings or {})
    private = Path(config.get("IDP_KEY_PATH", "data/signing.key")).read_bytes()
    public = serialization.load_pem_private_key(private, password=None).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    password_hash = config.get("IDP_PASSWORD_HASH", "")
    salt, digest = password_hash.split(":")
    if len(bytes.fromhex(salt)) < 16 or len(bytes.fromhex(digest)) != 32:
        raise ValueError("Hash de contraseña inválido")
    admin = config.get("IDP_ADMIN_TOKEN", "")
    if len(admin) < 32:
        raise ValueError("Configura IDP_ADMIN_TOKEN")
    issuer = config.get("IDP_ISSUER", "cybersecurity-labs")
    audience = config.get("IDP_AUDIENCE", "lab-services")
    username = config.get("IDP_USERNAME", "analyst")
    allowed = set(config.get("IDP_SCOPES", "pki:read pki:sign").split())
    ttl = int(config.get("IDP_TOKEN_TTL", "300"))
    if not 1 <= ttl <= 3600:
        raise ValueError("TTL debe estar entre 1 y 3600 segundos")
    database = Path(config.get("IDP_DB", "data/revocations.sqlite3"))
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS revoked (jti TEXT PRIMARY KEY)")
    bearer = HTTPBearer(auto_error=False)
    app = FastAPI(title="Identity Provider de laboratorio")
    attempts, lock = defaultdict(deque), threading.Lock()

    def unauthorized():
        return HTTPException(401, "Token o credenciales inválidos", headers={"WWW-Authenticate": "Bearer"})

    def credentials(auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if auth is None:
            raise unauthorized()
        return auth.credentials

    def decode(token=Depends(credentials)):
        try:
            claims = jwt.decode(token, public, algorithms=["RS256"], issuer=issuer, audience=audience,
                options={"require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "scope"]})
            if not all(isinstance(claims[k], str) and claims[k] for k in ("sub", "jti")) or not isinstance(claims["scope"], str):
                raise ValueError("Claims inválidos")
            with sqlite3.connect(database) as db:
                if db.execute("SELECT 1 FROM revoked WHERE jti=?", (claims["jti"],)).fetchone():
                    raise ValueError("Revocado")
            return claims
        except (jwt.PyJWTError, ValueError):
            raise unauthorized() from None

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/login")
    def login(request: Request, response: Response, form: OAuth2PasswordRequestForm = Depends()):
        if len(form.username) > 128 or len(form.password) > 1024:
            raise unauthorized()
        client = request.client.host if request.client else "unknown"
        now = time.time()
        with lock:
            for address in list(attempts):
                while attempts[address] and attempts[address][0] < now - 60:
                    attempts[address].popleft()
                if not attempts[address]:
                    del attempts[address]
            if len(attempts[client]) >= 10:
                raise HTTPException(429, "Demasiados intentos", headers={"Retry-After": "60"})
            attempts[client].append(now)
        valid_password = hmac.compare_digest(hash_password(form.password, salt), password_hash)
        if not hmac.compare_digest(form.username.encode(), username.encode()) or not valid_password:
            raise unauthorized()
        scopes = set(form.scopes) if form.scopes else allowed
        if not scopes <= allowed:
            raise HTTPException(403, "Scopes no autorizados")
        claims = {"iss": issuer, "aud": audience, "sub": username, "iat": int(now), "nbf": int(now),
                  "exp": int(now) + ttl, "jti": secrets.token_hex(16), "scope": " ".join(sorted(scopes))}
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return {"access_token": jwt.encode(claims, private, algorithm="RS256"),
                "token_type": "bearer", "expires_in": ttl, "scope": claims["scope"]}

    @app.get("/verify")
    def verify(response: Response, scope: str = "", claims=Depends(decode)):
        response.headers["Cache-Control"] = "no-store"
        if not set(scope.split()) <= set(claims["scope"].split()):
            raise HTTPException(403, "Scopes insuficientes")
        return {"active": True, "claims": claims}

    class Revocation(BaseModel):
        jti: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9-]+$")

    @app.post("/revoke")
    def revoke(body: Revocation, token=Depends(credentials)):
        if not hmac.compare_digest(token.encode(), admin.encode()):
            raise unauthorized()
        with sqlite3.connect(database) as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (body.jti,))
        return {"revoked": True}

    return app
