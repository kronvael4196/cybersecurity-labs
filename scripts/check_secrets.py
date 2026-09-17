"""Check Git's staged/tracked content before publication; never print matched secret values."""
import re
import subprocess
import sys
from pathlib import PurePosixPath

PATTERNS = [re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
            re.compile(rb"gh[pousr]_[A-Za-z0-9]{30,}"), re.compile(rb"github_pat_[A-Za-z0-9_]{50,}"),
            re.compile(rb"AKIA[0-9A-Z]{16}")]
DENIED_SUFFIXES = {".key", ".p12", ".pfx", ".pem", ".sqlite3", ".pcap", ".pcapng"}


def check():
    paths = subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")
    failures = []
    for name in filter(None, paths):
        path = PurePosixPath(name)
        if (path.name.startswith(".env") and path.name != ".env.example") or path.suffix in DENIED_SUFFIXES or any(part in {"data", "tls", ".venv", "captures"} for part in path.parts):
            failures.append(f"Archivo privado versionado: {name}")
            continue
        content = subprocess.check_output(["git", "show", ":" + name])
        if any(pattern.search(content) for pattern in PATTERNS):
            failures.append(f"Posible secreto en: {name}")
    for failure in failures:
        print(failure)
    print(f"Revisión de {sum(bool(name) for name in paths)} archivos: {len(failures)} hallazgos.")
    return bool(failures)


if __name__ == "__main__":
    sys.exit(check())
