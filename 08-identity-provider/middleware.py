"""Online verification preserves revocations; adapters fail closed on IDP outage."""
import httpx


class IdentityError(Exception):
    def __init__(self, status):
        self.status = status


def verify_bearer(header, base_url, scopes=()):
    scheme, _, token = (header or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise IdentityError(401)
    try:
        with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
            response = client.get(base_url.rstrip("/") + "/verify",
                headers={"Authorization": "Bearer " + token}, params={"scope": " ".join(scopes)})
        if response.status_code in (401, 403):
            raise IdentityError(response.status_code)
        response.raise_for_status()
        result = response.json()
        claims = result["claims"]
        if result.get("active") is not True or not set(scopes) <= set(claims["scope"].split()):
            raise ValueError("Respuesta inválida")
        return claims
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        raise IdentityError(503) from None


def require_scopes(base_url, *scopes):
    from fastapi import Header, HTTPException

    def dependency(authorization: str | None = Header(default=None)):
        try:
            return verify_bearer(authorization, base_url, scopes)
        except IdentityError as error:
            raise HTTPException(error.status, "Acceso denegado por el proveedor de identidad") from None
    return dependency


def protect_flask(app, base_url, scopes=("pki:read",), prefix="/api/"):
    from flask import abort, g, request

    @app.before_request
    def authorize():
        if request.path.startswith(prefix):
            try:
                g.identity = verify_bearer(request.headers.get("Authorization"), base_url, scopes)
            except IdentityError as error:
                abort(error.status)
