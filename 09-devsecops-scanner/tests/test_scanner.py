import json
from pathlib import Path
import secrets
import subprocess
import sys

import pytest
from scanner import main, scan


@pytest.mark.parametrize("kind", ["github", "jwt", "pem", "password", "aws", "env"])
def test_fake_secrets_fail_without_exposing_value(tmp_path, capsys, kind):
    examples = {"github": "gh" + "p_" + "A" * 36,
                "jwt": "eyJ" + "a" * 20 + "." + "b" * 20 + "." + "c" * 20,
                "pem": "-----BEGIN " + "RSA PRIVATE KEY-----",
                "password": 'password = "' + secrets.token_hex(16) + '"',  # secret-scan: allow -- constructs an ephemeral scanner fixture
                "aws": "AK" + "IA" + "A" * 16,
                "env": "ADMIN_TOKEN=" + secrets.token_urlsafe(32)}
    value = examples[kind]
    (tmp_path / "config.txt").write_text(value)
    assert main([str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert value not in output
    assert json.loads(output)["findings"][0]["path"] == "config.txt"


def test_cli_exit_code(tmp_path):
    (tmp_path / "secret.txt").write_text("gh" + "p_" + "B" * 36)
    result = subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] / "scanner.py"), str(tmp_path)], capture_output=True)
    assert result.returncode == 1


def test_gitignore_negation_and_tracked_files(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text("ignored.txt\n*.local\n!keep.local\n")
    secret = "gh" + "p_" + "C" * 36
    for name in ("ignored.txt", "skip.local", "keep.local"):
        (tmp_path / name).write_text(secret)
    assert [item["path"] for item in scan(tmp_path)["findings"]] == ["keep.local"]
    subprocess.run(["git", "-C", str(tmp_path), "add", "-f", "ignored.txt"], check=True)
    assert {item["path"] for item in scan(tmp_path)["findings"]} == {"ignored.txt", "keep.local"}


def test_image_exclusion_and_invalid_path(tmp_path):
    (tmp_path / "image.png").write_text("gh" + "p_" + "D" * 36)
    assert scan(tmp_path)["findings"] == []
    assert main([str(tmp_path / "missing")]) == 2
