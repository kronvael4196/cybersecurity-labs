"""Preserve sshd stderr as timestamped JSON lines for Logstash."""
import datetime
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid


def event(message):
    return {
        "@timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "message": message.rstrip(),
        "event": {"id": str(uuid.uuid4()), "dataset": "ssh.auth"},
        "host": {"name": "ssh-lab"},
    }


def main():
    password = os.environ["SSH_PASSWORD"]
    if not password or any(c in password for c in "\r\n:"):
        raise ValueError("SSH_PASSWORD debe ser no vacía y no contener saltos ni ':'")
    subprocess.run(["chpasswd"], input=f"analyst:{password}\n", text=True, check=True)
    key = Path("/etc/ssh/keys/ssh_host_ed25519_key")
    if not key.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    process = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: process.terminate())
    with open("/logs/auth.jsonl", "a", encoding="utf-8", buffering=1) as log:
        for line in process.stdout:
            log.write(json.dumps(event(line)) + "\n")
            print(line.rstrip(), flush=True)
    sys.exit(process.wait())


if __name__ == "__main__":
    main()
