import os
from pathlib import Path
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from auth_server import hash_password


def initialize(root=None):
    os.umask(0o077)
    root = Path(root or Path(__file__).resolve().parent)
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    key_path = data / "signing.key"
    if not key_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with key_path.open("xb") as file:
            file.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        key_path.chmod(0o600)
    env = root / ".env"
    if not env.exists():
        password = secrets.token_urlsafe(32)
        with env.open("x", encoding="utf-8") as file:
            file.write("IDP_USERNAME=analyst\nIDP_PASSWORD_HASH=" + hash_password(password)
                       + "\nIDP_ADMIN_TOKEN=" + secrets.token_urlsafe(32) + "\n")  # secret-scan: allow -- generated credential, not a literal secret
        # The service receives only the hash; this local client credential is never mounted.
        (data / "login-password.txt").write_text(password, encoding="utf-8")
    print("Identidad local preparada; credenciales en .env y data/login-password.txt (ignorados por Git).")


if __name__ == "__main__":
    initialize()
