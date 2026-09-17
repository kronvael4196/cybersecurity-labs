import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, IPvAnyAddress

import actions


class Source(BaseModel):
    ip: IPvAnyAddress


class Event(BaseModel):
    kind: Literal["alert"]


class Rule(BaseModel):
    id: Literal["ssh-repeated-failures"]


class Alert(BaseModel):
    source: Source
    event: Event
    rule: Rule
    timestamp: str = Field(alias="@timestamp", min_length=1, max_length=80)
    token_jti: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9-]+$")


def create_app(token=None, database=None, dry_run=None):
    token = token if token is not None else os.getenv("SOAR_WEBHOOK_TOKEN", "")
    if len(token) < 32:
        raise ValueError("Configura SOAR_WEBHOOK_TOKEN de al menos 32 caracteres")
    dry_run = (os.getenv("SOAR_MODE", "dry-run") != "live") if dry_run is None else dry_run
    database = Path(database or os.getenv("SOAR_DB", "data/actions.sqlite3"))
    database.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE IF NOT EXISTS actions (id TEXT PRIMARY KEY, result TEXT NOT NULL)")
    lock = threading.Lock()
    app = FastAPI(title="Mini SOAR")
    bearer = HTTPBearer(auto_error=False)

    def authorize(auth: HTTPAuthorizationCredentials | None = Depends(bearer)):
        if auth is None or not hmac.compare_digest(auth.credentials.encode(), token.encode()):
            raise HTTPException(401, "Webhook no autorizado", headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "dry-run" if dry_run else "live"}

    @app.post("/webhook/alert", dependencies=[Depends(authorize)])
    def webhook(alert: Alert):
        identity = hashlib.sha256((str(dry_run) + alert.model_dump_json()).encode()).hexdigest()
        ip = str(alert.source.ip)
        # Single worker + persistent per-action checkpoints: successful actions are not replayed.
        with lock, sqlite3.connect(database) as db:
            row = db.execute("SELECT result FROM actions WHERE id=?", (identity,)).fetchone()
            results = json.loads(row[0]) if row else {}
            steps = {"block_ip": lambda: actions.block_ip(ip, dry_run=dry_run,
                        allowed_networks=os.getenv("SOAR_ALLOWED_NETWORKS", "")),
                     "notify": lambda: actions.notify(ip, dry_run=dry_run)}
            if alert.token_jti:
                steps["revoke_token"] = lambda: actions.revoke_token(alert.token_jti, dry_run=dry_run)
            duplicate = all(name in results for name in steps)
            for name, action in steps.items():
                if name not in results:
                    try:
                        results[name] = action()
                    except Exception:
                        # Never return exceptions containing webhook URLs or credentials.
                        raise HTTPException(502, f"Acción {name} fallida; se puede reintentar") from None
                    db.execute("INSERT OR REPLACE INTO actions VALUES (?, ?)", (identity, json.dumps(results)))
                    db.commit()
        return {"id": identity, "duplicate": duplicate, "actions": list(results.values())}

    return app
