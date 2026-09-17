"""Real HTTP and SSH checks against the three new Compose services; prints no credentials."""
import importlib.util
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import time

import httpx
import paramiko

ROOT = Path(__file__).resolve().parents[1]


def env(project):
    return dict(line.split("=", 1) for line in (ROOT / project / ".env").read_text().splitlines() if "=" in line)


def main():
    soar, identity = env("06-soar-automation"), env("08-identity-provider")
    with httpx.Client(timeout=10, trust_env=False) as client:
        response = client.post("http://localhost:8001/login", data={"username": identity["IDP_USERNAME"],
            "password": (ROOT / "08-identity-provider/data/login-password.txt").read_text(), "scope": "pki:read"})
        assert response.status_code == 200, "Login fallido"
        bearer = {"Authorization": "Bearer " + response.json()["access_token"]}
        verified = client.get("http://localhost:8001/verify?scope=pki:read", headers=bearer)
        assert verified.status_code == 200, "Verificación fallida"
        jti = verified.json()["claims"]["jti"]
        alert = {"@timestamp": "2026-09-17T00:00:00Z", "event": {"kind": "alert"},
                 "source": {"ip": "192.0.2.5"}, "rule": {"id": "ssh-repeated-failures"}, "token_jti": jti}
        response = client.post("http://localhost:8080/webhook/alert", json=alert,
            headers={"Authorization": "Bearer " + soar["SOAR_WEBHOOK_TOKEN"]})
        assert response.status_code == 200, "Webhook fallido"
        assert {a["status"] for a in response.json()["actions"]} <= {"simulated", "not_configured"}
        # Exercise the actual SOAR -> IDP adapter without touching any firewall or messaging service.
        spec = importlib.util.spec_from_file_location("soar_actions", ROOT / "06-soar-automation/actions.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        os.environ.update(IDP_URL="http://localhost:8001", IDP_ADMIN_TOKEN=identity["IDP_ADMIN_TOKEN"])
        assert module.revoke_token(jti, dry_run=False)["status"] == "applied"
        assert client.get("http://localhost:8001/verify", headers=bearer).status_code == 401
    for attempt in range(40):
        try:
            connection = socket.create_connection(("127.0.0.1", 2223), timeout=2)
            connection.close()
            break
        except OSError:
            if attempt == 39:
                raise
            time.sleep(1)
    client = paramiko.SSHClient()
    # Trust only the public host key explicitly copied out of this disposable CI container.
    key_data = (ROOT / "artifacts/honeypot-host.pub").read_text().split()[1]
    key = paramiko.RSAKey(data=base64.b64decode(key_data))
    client.get_host_keys().add("[127.0.0.1]:2223", key.get_name(), key)
    try:
        client.connect("127.0.0.1", port=2223, username="ci-visitor", password=secrets.token_urlsafe(24),
                       allow_agent=False, look_for_keys=False, timeout=5)
        _, stdout, _ = client.exec_command("whoami", timeout=5)
        assert stdout.read() == b"guest\n"
    finally:
        client.close()
    print(json.dumps({"soar_webhook": "passed (dry-run)", "idp_signature_scopes_revocation": "passed",
                      "honeypot_ssh": "passed", "external_notifications": "not_sent"}))


if __name__ == "__main__":
    main()
