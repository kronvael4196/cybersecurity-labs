"""WireGuard lab provisioning. Runs only inside the project's network namespaces."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def initialize():
    os.umask(0o077)
    for side in ("server", "client"):
        folder = Path("/" + side)
        folder.mkdir(exist_ok=True)
        key = folder / "private.key"
        if not key.exists():
            key.write_text(run("wg", "genkey", capture_output=True).stdout)
        public = run("wg", "pubkey", input=key.read_text(), capture_output=True).stdout
        (folder / "public.key").write_text(public)
    server_private = Path("/server/private.key").read_text().strip()
    client_private = Path("/client/private.key").read_text().strip()
    server_public = Path("/server/public.key").read_text().strip()
    client_public = Path("/client/public.key").read_text().strip()
    Path("/server/wg.conf").write_text(f"[Interface]\nPrivateKey = {server_private}\nListenPort = 51820\n\n[Peer]\nPublicKey = {client_public}\nAllowedIPs = 10.77.0.2/32\n")
    Path("/client/wg.conf").write_text(f"[Interface]\nPrivateKey = {client_private}\n\n[Peer]\nPublicKey = {server_public}\nEndpoint = 172.30.77.2:51820\nAllowedIPs = 10.77.0.0/24, 172.30.78.0/24\nPersistentKeepalive = 25\n")
    print("Claves y configuraciones preparadas; no se han publicado claves privadas.")


def start(role):
    # On a container restart its network namespace may still hold the old interface.
    subprocess.run(["ip", "link", "del", "wg0"], capture_output=True)
    run("ip", "link", "add", "wg0", "type", "wireguard")
    run("wg", "setconf", "wg0", "/keys/wg.conf")
    run("ip", "address", "add", "10.77.0.1/24" if role == "server" else "10.77.0.2/24", "dev", "wg0")
    run("ip", "link", "set", "dev", "wg0", "mtu", "1420", "up")
    if role == "client":
        run("ip", "route", "replace", "172.30.78.0/24", "dev", "wg0")
    else:
        # These chains belong to this container's own network namespace.
        run("iptables", "-F", "FORWARD")
        run("iptables", "-P", "FORWARD", "DROP")
        run("iptables", "-A", "FORWARD", "-i", "wg0", "-s", "10.77.0.2/32", "-d", "172.30.78.0/24", "-j", "ACCEPT")
        run("iptables", "-A", "FORWARD", "-o", "wg0", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        run("iptables", "-t", "nat", "-F", "POSTROUTING")
        run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.77.0.0/24", "-d", "172.30.78.0/24", "-j", "MASQUERADE")
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    print(f"WireGuard {role} listo.", flush=True)
    while not stopping:
        time.sleep(1)
    run("ip", "link", "del", "wg0")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) == 2 else ""
    if command == "init":
        initialize()
    elif command in ("server", "client"):
        start(command)
    else:
        sys.exit("Uso: vpn.py init|server|client")
