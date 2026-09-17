"""Import a reproducible Kibana dashboard with real SSH event and alert counters."""
import json
import urllib.request
import uuid


def objects():
    result, panels, references = [], [], []
    for number, (slug, title, index, query) in enumerate([
        ("events", "Eventos SSH", "mini-siem-logs", ""),
        ("failures", "Autenticaciones fallidas", "mini-siem-logs", 'event.outcome: "failure"'),
        ("alerts", "Alertas de fuerza bruta", "mini-siem-alerts", ""),
    ], 1):
        identity = "mini-siem-metric-" + slug
        search = {"indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                  "query": {"language": "kuery", "query": query}, "filter": []}
        result.append({"type": "visualization", "id": identity, "attributes": {
            "title": title, "description": "Contador de datos reales del laboratorio",
            "visState": json.dumps({"title": title, "type": "metric", "params": {
                "addTooltip": True, "addLegend": False, "type": "metric",
                "metric": {"style": {"fontSize": 60, "bgFill": "#000", "bgColor": False,
                                      "labelColor": False, "subText": ""},
                           "percentageMode": False, "useRanges": False, "colorSchema": "Green to Red",
                           "metricColorMode": "None", "colorsRange": [{"from": 0, "to": 10000}],
                           "labels": {"show": True}, "invertColors": False}},
                "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}]}),
            "uiStateJSON": "{}", "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(search)}},
            "references": [{"type": "index-pattern", "id": index, "name": "kibanaSavedObjectMeta.searchSourceJSON.index"}]})
        panels.append({"type": "visualization", "panelIndex": str(number), "panelRefName": f"panel_{number}",
                       "gridData": {"x": (number - 1) * 16, "y": 0, "w": 16, "h": 15, "i": str(number)},
                       "embeddableConfig": {}})
        references.append({"type": "visualization", "id": identity, "name": f"panel_{number}"})
    result.append({"type": "dashboard", "id": "mini-siem-overview", "references": references,
        "attributes": {"title": "Mini SIEM — actividad SSH", "description": "Autenticaciones y alertas del laboratorio",
                       "panelsJSON": json.dumps(panels), "optionsJSON": '{"useMargins":true,"hidePanelTitles":false}',
                       "timeRestore": True, "timeFrom": "now-15m", "timeTo": "now", "version": 1,
                       "kibanaSavedObjectMeta": {"searchSourceJSON": '{"query":{"language":"kuery","query":""},"filter":[]}'}}})
    return result


def main():
    boundary = uuid.uuid4().hex
    ndjson = "\n".join(json.dumps(item, ensure_ascii=False) for item in objects()) + "\n"
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="dashboard.ndjson"\r\n'
            f'Content-Type: application/ndjson\r\n\r\n{ndjson}\r\n--{boundary}--\r\n').encode()
    req = urllib.request.Request("http://localhost:5601/api/saved_objects/_import?overwrite=true", data=body,
          headers={"kbn-xsrf": "lab", "Content-Type": f"multipart/form-data; boundary={boundary}"})
    with urllib.request.urlopen(req, timeout=30) as response:
        result = json.load(response)
    if not result.get("success"):
        raise RuntimeError(json.dumps(result))
    print("Dashboard importado: http://localhost:5601/app/dashboards#/view/mini-siem-overview")


if __name__ == "__main__":
    main()
