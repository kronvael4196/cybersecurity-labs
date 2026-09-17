"""Create local credentials without printing them or overwriting existing secrets."""
import os
from pathlib import Path
import secrets

path = Path(__file__).resolve().parent / ".env"
os.umask(0o077)
try:
    with path.open("x", encoding="utf-8") as file:
        file.write(f"PKI_ADMIN_TOKEN={secrets.token_urlsafe(36)}\nPKI_CA_PASSWORD={secrets.token_urlsafe(36)}\n")
except FileExistsError:
    print(".env ya existe; se conservan sus credenciales.")
else:
    print(".env creado. Abre el archivo para obtener el token de acceso; conserva la contraseña de la CA.")
