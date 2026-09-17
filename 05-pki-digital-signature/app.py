import hmac
import io
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from flask import Flask, abort, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException

from pki import PKI


def load_local_env():
    path = Path(__file__).resolve().parent / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                key, value = line.split("=", 1)
                if key in {"PKI_ADMIN_TOKEN", "PKI_CA_PASSWORD"}:
                    os.environ.setdefault(key, value)


def create_app(settings=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=12 * 1024 * 1024,
                      PKI_ADMIN_TOKEN=os.getenv("PKI_ADMIN_TOKEN", ""),
                      PKI_CA_PASSWORD=os.getenv("PKI_CA_PASSWORD", ""),
                      PKI_DATA_DIR=os.getenv("PKI_DATA_DIR", str(Path(__file__).resolve().parent / "data")))
    if settings:
        app.config.update(settings)
    token = app.config["PKI_ADMIN_TOKEN"]
    if len(token) < 32:
        raise ValueError("PKI_ADMIN_TOKEN debe tener al menos 32 caracteres; ejecuta init_env.py")
    authority = PKI(app.config["PKI_DATA_DIR"], app.config["PKI_CA_PASSWORD"])
    app.extensions["pki"] = authority

    @app.before_request
    def authorize():
        if request.path.startswith("/api/"):
            supplied = request.headers.get("X-Admin-Token", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                abort(401, "Token de acceso requerido o inválido")

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(HTTPException)
    def http_error(error):
        return jsonify(error=error.description), error.code

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    @app.get("/ca.pem")
    def ca():
        return send_file(io.BytesIO(authority.ca.public_bytes(serialization.Encoding.PEM)),
                         mimetype="application/x-pem-file", download_name="lab-ca.pem", as_attachment=True)

    @app.get("/crl.pem")
    def crl():
        return send_file(io.BytesIO(authority.crl().public_bytes(serialization.Encoding.PEM)),
                         mimetype="application/x-pem-file", download_name="lab-crl.pem", as_attachment=True)

    @app.get("/api/certificates")
    def certificates():
        return jsonify(authority.certificates())

    def object_body():
        body = request.get_json()
        if not isinstance(body, dict):
            raise ValueError("Se requiere un objeto JSON")
        return body

    @app.post("/api/certificates")
    def issue():
        body = object_body()
        bundle, serial = authority.issue(body.get("name"), body.get("algorithm", "ECC"),
                                         body.get("days", 30), body.get("password"))
        response = send_file(io.BytesIO(bundle), mimetype="application/x-pkcs12",
                             download_name=f"certificate-{serial}.p12", as_attachment=True)
        response.headers["X-Certificate-Serial"] = serial
        return response

    @app.post("/api/certificates/<serial>/revoke")
    def revoke(serial):
        authority.revoke(serial, object_body().get("reason", "Revocación solicitada"))
        return jsonify(revoked=True, serial=serial)

    def upload(name):
        file = request.files.get(name)
        if file is None:
            raise ValueError(f"Archivo requerido: {name}")
        return file.read()

    @app.post("/api/sign")
    def sign():
        package = authority.sign(upload("file"), upload("p12"), request.form.get("password", ""))
        return jsonify(package)

    @app.post("/api/verify")
    def verify():
        try:
            package = json.loads(upload("signature"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("El archivo de firma debe ser JSON válido") from error
        return jsonify(authority.verify(upload("file"), package))

    return app


if __name__ == "__main__":
    from waitress import serve
    load_local_env()
    serve(create_app(), host=os.getenv("BIND_HOST", "127.0.0.1"), port=5005, threads=4)
