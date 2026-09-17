"""Generate local credentials without printing or overwriting existing values."""
import os
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
os.umask(0o077)
path = ROOT / "01-mini-siem/.env"
if not path.exists():
    example = path.with_name(".env.example").read_text(encoding="utf-8")
    with path.open("x", encoding="utf-8") as file:
        file.write(example.replace("replace-with-your-local-lab-password", secrets.token_urlsafe(32)))
subprocess.run([sys.executable, str(ROOT / "05-pki-digital-signature/init_env.py")], check=True)
print("Credenciales locales preparadas. Los archivos .env quedan fuera del repositorio.")
