"""Run a new lab on loopback, loading only its own ignored .env file."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
MODULES = {"06": "06-soar-automation", "07": "07-ssh-honeypot", "08": "08-identity-provider"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("module", choices=MODULES)
    args = parser.parse_args()
    folder = ROOT / MODULES[args.module]
    os.chdir(folder)
    sys.path.insert(0, str(folder))
    env = folder / ".env"
    if env.exists():
        for line in env.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key, value)
    if args.module == "07":
        from honeypot import Honeypot
        server = Honeypot(host="127.0.0.1", port=2223)
        try:
            server.serve_forever()
        finally:
            server.close()
    else:
        import uvicorn
        target = "app:create_app" if args.module == "06" else "auth_server:create_app"
        if args.module == "06":
            os.environ["SOAR_MODE"] = "dry-run"
        uvicorn.run(target, factory=True, host="127.0.0.1", port=8080 if args.module == "06" else 8001)
