"""Forward one real Mini SIEM alert file (raw _source or Elasticsearch search result)."""
import argparse
import json
import os
from pathlib import Path

import httpx

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file", type=Path)
    parser.add_argument("--url", default="http://localhost:8080")
    args = parser.parse_args()
    payload = json.loads(args.file.read_text(encoding="utf-8"))
    alerts = [item["_source"] for item in payload["hits"]["hits"]] if "hits" in payload else [payload]
    with httpx.Client(timeout=10, follow_redirects=False, trust_env=False) as client:
        for alert in alerts:
            response = client.post(args.url.rstrip("/") + "/webhook/alert", json=alert,
                headers={"Authorization": "Bearer " + os.environ["SOAR_WEBHOOK_TOKEN"]})
            if response.is_error:
                raise SystemExit(f"Webhook rechazado: HTTP {response.status_code}")
            print(json.dumps(response.json()))
