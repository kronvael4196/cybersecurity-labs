"""Small polling rule engine and idempotent ELK setup; Python standard library only."""
import datetime as dt
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

ES = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
KIBANA = os.getenv("KIBANA_URL", "http://kibana:5601")
RULE_ID = "ssh-repeated-failures"


def request(path, body=None, method=None, base=ES):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method,
                                 headers={"Content-Type": "application/json", "kbn-xsrf": "mini-siem"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.load(response)


def positive_setting(name, default):
    value = int(os.getenv(name, default))
    if value <= 0:
        raise ValueError(f"{name} debe ser mayor que cero")
    return value


def setup():
    properties = {
        "@timestamp": {"type": "date"},
        "message": {"type": "text"},
        "source": {"properties": {"ip": {"type": "ip"}, "port": {"type": "integer"}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "event": {"properties": {key: {"type": "keyword"} for key in
                                   ("id", "dataset", "category", "outcome", "kind")}},
        "rule": {"properties": {"id": {"type": "keyword"}, "name": {"type": "keyword"}}},
        "alert": {"properties": {"count": {"type": "integer"},
                                   "window_seconds": {"type": "integer"},
                                   "severity": {"type": "keyword"}}},
    }
    request("/_index_template/mini-siem", {
        "index_patterns": ["mini-siem-*"],
        "template": {"settings": {"number_of_shards": 1, "number_of_replicas": 0},
                     "mappings": {"properties": properties}},
    }, "PUT")
    for index in ("mini-siem-logs", "mini-siem-alerts"):
        try:
            request("/" + index, {}, "PUT")
        except urllib.error.HTTPError as error:
            detail = json.loads(error.read())
            if detail.get("error", {}).get("type") != "resource_already_exists_exception":
                raise
    print("Índices y mappings preparados.")


def setup_kibana():
    for attempt in range(90):
        try:
            for kind in ("logs", "alerts"):
                request("/api/data_views/data_view", {
                    "data_view": {"id": f"mini-siem-{kind}", "title": f"mini-siem-{kind}",
                                  "name": f"Mini SIEM — {kind}", "timeFieldName": "@timestamp"},
                    "override": True,
                }, "POST", KIBANA)
            print("Vistas de datos creadas en Kibana.")
            return
        except (urllib.error.URLError, TimeoutError) as error:
            print(f"Esperando Kibana ({attempt + 1}/90): {error}", flush=True)
            time.sleep(5)
    raise RuntimeError("Kibana no estuvo disponible; vuelve a ejecutar el servicio kibana-setup")


def window_query(now, window):
    return {"bool": {"filter": [
        {"term": {"event.outcome": "failure"}},
        {"term": {"event.dataset": "ssh.auth"}},
        {"range": {"@timestamp": {"gte": (now - dt.timedelta(seconds=window)).isoformat(),
                                   "lte": now.isoformat()}}},
    ]}}


def candidates(now, window):
    after = None
    while True:
        composite = {"size": 500, "sources": [{"ip": {"terms": {"field": "source.ip"}}}]}
        if after:
            composite["after"] = after
        result = request("/mini-siem-logs/_search", {
            "size": 0, "query": window_query(now, window),
            "aggs": {"ips": {"composite": composite}},
        })
        if result.get("timed_out") or result.get("_shards", {}).get("failed", 0):
            raise RuntimeError("Consulta incompleta; se reintentará")
        aggregation = result["aggregations"]["ips"]
        yield from aggregation["buckets"]
        after = aggregation.get("after_key")
        if not after or not aggregation["buckets"]:
            break


def should_alert(count, threshold, now, last_alert, cooldown):
    return count >= threshold and (last_alert is None or
                                  (now - last_alert).total_seconds() >= cooldown)


def detect_once(threshold, window, cooldown):
    now = dt.datetime.now(dt.timezone.utc)
    for bucket in candidates(now, window):
        count, ip = bucket["doc_count"], bucket["key"]["ip"]
        if count < threshold:
            continue
        previous = request("/mini-siem-alerts/_search", {
            "size": 1, "sort": [{"@timestamp": "desc"}],
            "query": {"bool": {"filter": [{"term": {"source.ip": ip}},
                                            {"term": {"rule.id": RULE_ID}}]}},
        })["hits"]["hits"]
        last = dt.datetime.fromisoformat(previous[0]["_source"]["@timestamp"]) if previous else None
        if not should_alert(count, threshold, now, last, cooldown):
            continue
        alert = {
            "@timestamp": now.isoformat(), "event": {"kind": "alert"}, "source": {"ip": ip},
            "rule": {"id": RULE_ID, "name": "Posible fuerza bruta SSH"},
            "alert": {"count": count, "window_seconds": window, "severity": "high"},
            "message": f"{count} fallos SSH desde {ip} en {window} segundos",
        }
        identity = hashlib.sha256(f"{RULE_ID}|{ip}|{now.isoformat()}".encode()).hexdigest()
        request(f"/mini-siem-alerts/_doc/{identity}?refresh=wait_for", alert, "PUT")
        print(json.dumps(alert, ensure_ascii=False), flush=True)


def detect():
    threshold = positive_setting("FAILURE_THRESHOLD", "5")
    window = positive_setting("WINDOW_SECONDS", "60")
    cooldown = positive_setting("COOLDOWN_SECONDS", "120")
    poll = positive_setting("POLL_SECONDS", "5")
    print(f"Regla activa: {threshold} fallos/{window}s; cooldown={cooldown}s; sondeo={poll}s")
    while True:
        try:
            detect_once(threshold, window, cooldown)
        except (urllib.error.URLError, TimeoutError, RuntimeError) as error:
            print(f"Error temporal del detector: {error}", flush=True)
        time.sleep(poll)


def verify(since):
    """Wait for actual SSH events and an alert from this smoke-test run."""
    for _ in range(36):
        filters = [{"range": {"@timestamp": {"gte": since}}}, {"term": {"source.ip": "127.0.0.1"}}]
        counts = {}
        for outcome in ("failure", "success"):
            counts[outcome] = request("/mini-siem-logs/_count", {"query": {"bool": {"filter":
                filters + [{"term": {"event.outcome": outcome}}]}}})["count"]
        counts["alerts"] = request("/mini-siem-alerts/_count", {"query": {"bool": {"filter": filters}}})["count"]
        if counts["failure"] >= 5 and counts["success"] >= 1 and counts["alerts"] >= 1:
            print("Prueba integral OK: " + json.dumps(counts))
            return
        time.sleep(5)
    raise RuntimeError(f"Prueba integral incompleta: {counts}. Consulta logs de Logstash y detector.")


if __name__ == "__main__":
    commands = {"setup": setup, "kibana": setup_kibana, "detect": detect}
    if len(sys.argv) == 3 and sys.argv[1] == "verify":
        verify(sys.argv[2])
    elif len(sys.argv) == 2 and sys.argv[1] in commands:
        commands[sys.argv[1]]()
    else:
        sys.exit("Uso: app.py setup|kibana|detect|verify <fecha ISO>")
