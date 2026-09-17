"""Generate five real failed SSH logins and one successful login, only on localhost."""
import os
import subprocess


def login(password):
    return subprocess.run([
        "sshpass", "-e", "ssh", "-p", "22", "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=/tmp/mini-siem-known-hosts", "-o", "ConnectTimeout=5",
        "-o", "PreferredAuthentications=password", "-o", "NumberOfPasswordPrompts=1",
        "analyst@127.0.0.1", "true",
    ], env={**os.environ, "SSHPASS": password}, capture_output=True, text=True, timeout=15)


if __name__ == "__main__":
    for attempt in range(5):
        result = login(os.environ["SSH_PASSWORD"] + "-incorrecta")
        if result.returncode != 5:
            raise RuntimeError(f"Fallo inesperado en SSH: {result.stderr}")
        print(f"Fallo de autenticación {attempt + 1}/5 generado.", flush=True)
    result = login(os.environ["SSH_PASSWORD"])
    if result.returncode:
        raise RuntimeError(f"El acceso legítimo falló: {result.stderr}")
    print("Acceso legítimo verificado.")
