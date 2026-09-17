"""Remediation adapters. Dry-run is the default; no shell interpolation."""
import ipaddress
import os
import subprocess
from urllib.parse import urlsplit

import httpx


def block_ip(ip, *, dry_run=True, allowed_networks=""):
    address = ipaddress.ip_address(ip)
    if dry_run:
        return {"action": "block_ip", "status": "simulated", "ip": str(address)}
    networks = [ipaddress.ip_network(n.strip()) for n in allowed_networks.split(",") if n.strip()]
    if (address.is_loopback or address.is_multicast or address.is_unspecified
            or not any(address in network for network in networks)):
        raise ValueError("IP fuera del alcance de remediación configurado")
    binary = "iptables" if address.version == 4 else "ip6tables"
    rule = ["INPUT", "-s", str(address), "-j", "DROP"]
    check = subprocess.run([binary, "-w", "5", "-C", *rule], capture_output=True, timeout=10)
    if check.returncode == 1:
        subprocess.run([binary, "-w", "5", "-I", *rule], check=True, capture_output=True, timeout=10)
    elif check.returncode != 0:
        raise RuntimeError("No se pudo consultar el firewall")
    return {"action": "block_ip", "status": "applied", "ip": str(address)}


def revoke_token(jti, *, dry_run=True):
    if dry_run:
        return {"action": "revoke_token", "status": "simulated"}
    base = os.environ["IDP_URL"].rstrip("/")
    token = os.environ["IDP_ADMIN_TOKEN"]
    # Destination comes from operator configuration, never from a webhook payload.
    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
        response = client.post(base + "/revoke", json={"jti": jti},
                               headers={"Authorization": "Bearer " + token})
        response.raise_for_status()
    return {"action": "revoke_token", "status": "applied"}


def notify(ip, *, dry_run=True):
    url = os.getenv("NOTIFICATION_WEBHOOK_URL", "")
    if not url:
        return {"action": "notify", "status": "not_configured"}
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in {"hooks.slack.com", "discord.com"} or parsed.username:
        raise ValueError("Se requiere un webhook HTTPS de Slack o Discord")
    if dry_run:
        return {"action": "notify", "status": "simulated"}
    message = f"Mini SIEM: alerta SSH desde {ip}. Revisar el laboratorio."
    payload = {"text": message} if parsed.hostname == "hooks.slack.com" else {"content": message}
    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
        client.post(url, json=payload).raise_for_status()
    return {"action": "notify", "status": "sent"}
