import json
import secrets
import threading
from unittest.mock import Mock

import paramiko
import pytest

import geo_enricher
from honeypot import Honeypot, reply


@pytest.fixture
def server(tmp_path):
    instance = Honeypot(port=0, log_path=tmp_path / "honeypot.json", key_path=tmp_path / "host.key")
    thread = threading.Thread(target=instance.serve_forever)
    thread.start()
    yield instance
    instance.close()
    thread.join(timeout=3)
    assert not thread.is_alive()


def test_actual_ssh_login_records_credentials_and_simulates_shell(server):
    password = secrets.token_urlsafe(20)
    client = paramiko.SSHClient()
    client.get_host_keys().add(f"[127.0.0.1]:{server.port}", server.key.get_name(), server.key)
    try:
        client.connect("127.0.0.1", port=server.port, username="lab-visitor", password=password,
                       allow_agent=False, look_for_keys=False, timeout=5)
        _, stdout, _ = client.exec_command("whoami")
        assert stdout.read() == b"guest\n"
    finally:
        client.close()
    record = json.loads(server.log_path.read_text(encoding="utf-8").splitlines()[0])
    assert record["username"] == "lab-visitor" and record["password"] == password
    assert record["source"]["ip"] == "127.0.0.1" and record["geo"]["status"] == "non_public"


def test_commands_never_execute_host_operations(tmp_path):
    marker = tmp_path / "owned"
    assert reply(f"touch {marker}") == "Command unavailable\n"
    assert not marker.exists()


def test_geo_is_offline_for_private_ips_and_disabled_mode(monkeypatch):
    request = Mock()
    monkeypatch.setattr(geo_enricher, "urlopen", request)
    geo_enricher.geolocate.cache_clear()
    assert geo_enricher.geolocate("10.0.0.1", True)["status"] == "non_public"
    assert geo_enricher.geolocate("8.8.8.8", False)["status"] == "disabled"
    request.assert_not_called()


def test_geo_failure_preserves_login_record(tmp_path, monkeypatch):
    monkeypatch.setattr(geo_enricher, "urlopen", Mock(side_effect=TimeoutError))
    geo_enricher.geolocate.cache_clear()
    path = tmp_path / "honeypot.json"
    geo_enricher.write_event({"source": {"ip": "8.8.8.8"}}, path, True)
    assert json.loads(path.read_text())["geo"]["status"] == "unavailable"
