"""Bounded SSH decoy. The shell is a fixed Python simulation, never an OS shell."""
import datetime as dt
import os
from pathlib import Path
import socket
import threading
import time

import paramiko

from geo_enricher import write_event


def reply(command):
    return {"whoami": "guest\n", "id": "uid=1000(guest) gid=1000(guest)\n",
            "pwd": "/home/guest\n", "ls": "readme.txt\n", "cat readme.txt": "Training SSH server\n",
            "help": "whoami id pwd ls cat readme.txt exit\n"}.get(command, "Command unavailable\n")


class Session(paramiko.ServerInterface):
    def __init__(self, ip, log_path, geo_enabled):
        self.ip, self.log_path, self.geo_enabled = ip, log_path, geo_enabled
        self.ready = threading.Event()
        self.command = None

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        write_event({"@timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                     "event": {"dataset": "honeypot.auth", "outcome": "success"},
                     "source": {"ip": self.ip}, "username": username[:256], "password": password[:256]},
                    self.log_path, self.geo_enabled)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" and chanid == 0 else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, *args):
        return True

    def check_channel_shell_request(self, channel):
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        if len(command) > 512:
            return False
        self.command = command.decode("utf-8", errors="replace").strip()
        self.ready.set()
        return True


class Honeypot:
    def __init__(self, host="127.0.0.1", port=2222, log_path="logs/honeypot.json",
                 key_path="data/ssh_host.key", geo_enabled=False):
        self.log_path, self.geo_enabled = log_path, geo_enabled
        key_path = Path(key_path)
        key_path.parent.mkdir(parents=True, exist_ok=True)
        if not key_path.exists():
            paramiko.RSAKey.generate(2048).write_private_key_file(str(key_path))
            key_path.chmod(0o600)
        self.key = paramiko.RSAKey.from_private_key_file(str(key_path))
        self.socket = socket.socket()
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((host, port))
        self.port = self.socket.getsockname()[1]
        self.socket.listen(16)
        self.socket.settimeout(0.2)
        self.stopped = threading.Event()
        self.slots = threading.BoundedSemaphore(16)
        self.connections = set()
        self.lock = threading.Lock()

    def serve_forever(self):
        while not self.stopped.is_set():
            try:
                connection, address = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                connection.close()
                continue
            with self.lock:
                self.connections.add(connection)
            threading.Thread(target=self.handle, args=(connection, address[0]), daemon=True).start()

    def handle(self, connection, ip):
        transport = None
        try:
            connection.settimeout(10)
            transport = paramiko.Transport(connection)
            transport.banner_timeout = 10
            transport.auth_timeout = 10
            transport.add_server_key(self.key)
            session = Session(ip, self.log_path, self.geo_enabled)
            transport.start_server(server=session)
            channel = transport.accept(15)
            if channel is None or not session.ready.wait(10):
                return
            channel.settimeout(15)
            if session.command is not None:
                channel.sendall(reply(session.command).encode())
                channel.send_exit_status(0)
            else:
                channel.sendall(b"Training SSH server\r\n$ ")
                deadline = time.monotonic() + 60
                buffer = b""
                while not self.stopped.is_set() and time.monotonic() < deadline:
                    chunk = channel.recv(1)
                    if not chunk or chunk == b"\x04":
                        break
                    if chunk in (b"\r", b"\n"):
                        command = buffer.decode("utf-8", errors="replace").strip()
                        if command in {"exit", "logout"}:
                            break
                        channel.sendall(reply(command).encode() + b"$ ")
                        buffer = b""
                    elif len(buffer) < 512:
                        buffer += chunk
                    else:
                        break
            channel.close()
        except (OSError, EOFError, paramiko.SSHException):
            pass
        finally:
            if transport:
                transport.close()
            connection.close()
            with self.lock:
                self.connections.discard(connection)
            self.slots.release()

    def close(self):
        self.stopped.set()
        self.socket.close()
        with self.lock:
            for connection in self.connections:
                connection.close()


if __name__ == "__main__":
    os.umask(0o077)
    server = Honeypot(host=os.getenv("HONEYPOT_HOST", "127.0.0.1"),
                      port=int(os.getenv("HONEYPOT_PORT", "2222")),
                      geo_enabled=os.getenv("GEO_ENABLED", "false").lower() == "true")
    try:
        server.serve_forever()
    finally:
        server.close()
