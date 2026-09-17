"""Deliberately vulnerable exercises and the corresponding minimal fixes."""
import hmac
import os
import secrets
import sqlite3

from flask import Flask, abort, jsonify, render_template, request, session


def create_app(mode=None):
    mode = mode or os.getenv("LAB_MODE", "hardened")
    if mode not in {"vulnerable", "hardened"}:
        raise ValueError("LAB_MODE inválido")
    hardened = mode == "hardened"
    app = Flask(__name__)
    app.config.update(SECRET_KEY=secrets.token_hex(32), MAX_CONTENT_LENGTH=16 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      SESSION_COOKIE_NAME=f"lesson_{mode}")

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        if hardened:
            response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/")
    def index():
        session.setdefault("csrf", secrets.token_urlsafe(32))
        return render_template("index.html", mode=mode, token=session["csrf"],
                               email=session.get("email", "analyst@example.test"))

    @app.get("/search")
    def search():
        query = request.args.get("q", "")[:256]
        with sqlite3.connect(":memory:") as db:
            db.executescript("CREATE TABLE products(id INTEGER, name TEXT, public INTEGER);"
                             "INSERT INTO products VALUES (1,'Manual público',1),(2,'Nota privada del laboratorio',0);")
            try:
                if hardened:
                    rows = db.execute("SELECT id,name FROM products WHERE public=1 AND name LIKE ?",
                                      (f"%{query}%",)).fetchall()
                else:
                    # INTENCIONAL: comparación con la consulta parametrizada de arriba.
                    rows = db.execute(f"SELECT id,name FROM products WHERE public=1 AND name LIKE '%{query}%'").fetchall()
            except sqlite3.Error:
                abort(400, "Consulta inválida")
        return jsonify([{"id": row[0], "name": row[1]} for row in rows])

    @app.get("/echo")
    def echo():
        value = request.args.get("message", "Hola")[:1000]
        # INTENCIONAL: la variante vulnerable inserta HTML sin escape.
        if not hardened:
            return "<!doctype html><meta charset=utf-8><h1>Eco vulnerable</h1>" + value
        return render_template("echo.html", value=value)

    @app.post("/profile")
    def profile():
        if hardened and not hmac.compare_digest(session.get("csrf", "missing"), request.form.get("csrf", "")):
            abort(403, "Token CSRF inválido")
        email = request.form.get("email", "")
        if "@" not in email or len(email) > 120:
            abort(400, "Correo inválido")
        session["email"] = email
        return jsonify(email=email, mode=mode)

    return app


if __name__ == "__main__":
    from waitress import serve
    serve(create_app(), host=os.getenv("BIND_HOST", "127.0.0.1"), port=int(os.getenv("PORT", "8080")))
