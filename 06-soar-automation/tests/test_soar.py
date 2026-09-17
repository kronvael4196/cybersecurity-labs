import secrets
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

import actions
from app import create_app


@pytest.fixture
def setup(tmp_path):
    token = secrets.token_urlsafe(32)
    client = TestClient(create_app(token=token, database=tmp_path / "actions.sqlite3"))
    return client, {"Authorization": "Bearer " + token}


def payload(ip="192.0.2.12"):
    return {"@timestamp": "2026-09-17T00:00:00Z", "source": {"ip": ip},
            "event": {"kind": "alert"}, "rule": {"id": "ssh-repeated-failures"}}


def test_webhook_calls_block_and_duplicate_does_not_repeat(setup, monkeypatch):
    client, headers = setup
    block = Mock(return_value={"action": "block_ip", "status": "simulated"})
    monkeypatch.setattr(actions, "block_ip", block)
    response = client.post("/webhook/alert", json=payload(), headers=headers)
    assert response.status_code == 200
    block.assert_called_once_with("192.0.2.12", dry_run=True, allowed_networks="")
    assert client.post("/webhook/alert", json=payload(), headers=headers).json()["duplicate"]
    assert block.call_count == 1


def test_unauthorized_and_invalid_ip_do_not_act(setup, monkeypatch):
    client, headers = setup
    block = Mock()
    monkeypatch.setattr(actions, "block_ip", block)
    assert client.post("/webhook/alert", json=payload()).status_code == 401
    assert client.post("/webhook/alert", json=payload("1.2.3.4;whoami"), headers=headers).status_code == 422
    block.assert_not_called()


def test_failed_action_retries_without_repeating_completed_action(setup, monkeypatch):
    client, headers = setup
    block = Mock(return_value={"status": "simulated"})
    notification = Mock(side_effect=[RuntimeError("sensitive-url"), {"status": "sent"}])
    monkeypatch.setattr(actions, "block_ip", block)
    monkeypatch.setattr(actions, "notify", notification)
    response = client.post("/webhook/alert", json=payload(), headers=headers)
    assert response.status_code == 502 and "sensitive-url" not in response.text
    assert client.post("/webhook/alert", json=payload(), headers=headers).status_code == 200
    assert block.call_count == 1 and notification.call_count == 2


def test_token_revocation_adapter_is_selected(setup, monkeypatch):
    client, headers = setup
    revoke = Mock(return_value={"status": "simulated"})
    monkeypatch.setattr(actions, "revoke_token", revoke)
    assert client.post("/webhook/alert", json={**payload(), "token_jti": "test-id"}, headers=headers).status_code == 200
    revoke.assert_called_once_with("test-id", dry_run=True)


def test_dry_run_never_executes_firewall(monkeypatch):
    run = Mock()
    monkeypatch.setattr(actions.subprocess, "run", run)
    assert actions.block_ip("192.0.2.1")["status"] == "simulated"
    run.assert_not_called()


def test_live_firewall_scope_and_command_arguments(monkeypatch):
    run = Mock(side_effect=[Mock(returncode=1), Mock(returncode=0)])
    monkeypatch.setattr(actions.subprocess, "run", run)
    with pytest.raises(ValueError):
        actions.block_ip("127.0.0.1", dry_run=False, allowed_networks="0.0.0.0/0")
    with pytest.raises(ValueError):
        actions.block_ip("192.0.2.1", dry_run=False)
    actions.block_ip("192.0.2.1", dry_run=False, allowed_networks="192.0.2.0/24")
    assert run.call_args_list[1].args[0] == ["iptables", "-w", "5", "-I", "INPUT", "-s", "192.0.2.1", "-j", "DROP"]


def test_requires_configured_secret(tmp_path):
    with pytest.raises(ValueError):
        create_app(token="", database=tmp_path / "unused.db")
