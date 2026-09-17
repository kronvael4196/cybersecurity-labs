"""Run from this folder after docker compose up -d --build."""
import json
from pathlib import Path
import subprocess
import time


def compose(*args, **kwargs):
    return subprocess.run(["docker", "compose", *args], check=True, **kwargs)


compose("up", "-d", "capture")
time.sleep(2)
for attempt in range(20):
    result = subprocess.run(["docker", "compose", "exec", "-T", "client", "curl", "--fail", "--max-time", "5", "http://172.30.78.10:8080"], capture_output=True)
    if result.returncode == 0:
        break
    time.sleep(2)
else:
    raise SystemExit("No se pudo acceder al servicio privado por el túnel")
handshakes = compose("exec", "-T", "client", "wg", "show", "wg0", "latest-handshakes", capture_output=True, text=True).stdout
if not any(int(line.split()[-1]) > 0 for line in handshakes.splitlines()):
    raise SystemExit("No se observó un handshake WireGuard")
compose("stop", "capture")
compose("run", "--rm", "analyze")
report = json.loads(Path("reports/traffic.json").read_text(encoding="utf-8"))
if not report["cleartext_http"]:
    raise SystemExit("No se capturó HTTP en wg0; repite la prueba")
print("Prueba integral OK: túnel, handshake, acceso privado y captura HTTP comprobados.")
