"""Only public source IPs are sent to ipapi.co; never usernames or passwords."""
from functools import lru_cache
import ipaddress
import json
import os
from pathlib import Path
import threading
from urllib.request import urlopen

_lock = threading.Lock()


@lru_cache(maxsize=1024)
def geolocate(ip, enabled=False):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return {"status": "non_public"}
    if not enabled:
        return {"status": "disabled"}
    try:
        with urlopen(f"https://ipapi.co/{address}/json/", timeout=3) as response:
            data = json.loads(response.read(32768))
        if data.get("error"):
            return {"status": "unavailable"}
        return {"status": "ok", **{key: data.get(key) for key in ("country_code", "city", "latitude", "longitude", "org")}}
    except Exception:
        return {"status": "unavailable"}


def write_event(event, path="logs/honeypot.json", geo_enabled=False):
    record = {**event, "geo": geolocate(event["source"]["ip"], geo_enabled)}
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=True) + "\n")
