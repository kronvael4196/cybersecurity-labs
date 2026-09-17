"""Bounded TCP connect scanner with conservative service identification."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import errno
import html
import ipaddress
import json
from pathlib import Path
import socket
import time

HINTS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
         443: "https", 2222: "ssh", 3001: "http", 3002: "http", 3003: "http",
         5005: "http", 5601: "http", 8080: "http", 9200: "http"}


def parse_ports(spec):
    ports = set()
    for item in spec.split(","):
        bounds = item.split("-")
        if len(bounds) not in (1, 2):
            raise ValueError("Rango de puertos inválido")
        first, last = int(bounds[0]), int(bounds[-1])
        if not 1 <= first <= last <= 65535:
            raise ValueError("Los puertos deben estar entre 1 y 65535")
        ports.update(range(first, last + 1))
    return sorted(ports)


def parse_targets(spec, scopes):
    allowed = [ipaddress.ip_network(value, strict=False) for value in scopes]
    targets = set()
    for value in spec.split(","):
        network = ipaddress.ip_network(value.strip(), strict=False)
        if network.num_addresses > 1024:
            raise ValueError("Máximo 1024 direcciones por ejecución")
        for address in network.hosts():
            if address.is_multicast or address.is_unspecified:
                raise ValueError("Destino no unicast")
            if not any(address in scope for scope in allowed):
                raise ValueError(f"{address} está fuera del alcance autorizado --scope")
            targets.add(str(address))
            if len(targets) > 1024:
                raise ValueError("Máximo 1024 direcciones por ejecución")
    return sorted(targets, key=lambda ip: (ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip))))


def scan_port(ip, port, timeout, probe=False):
    started = time.monotonic()
    result = {"ip": ip, "port": port, "protocol": "tcp", "state": "unknown",
              "service_hint": HINTS.get(port, "unknown"), "service": "unconfirmed", "findings": []}
    family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            result["state"] = "open"
        except ConnectionRefusedError:
            result["state"] = "closed"
        except (TimeoutError, socket.timeout):
            result["state"] = "filtered_or_unreachable"
        except OSError as error:
            result["state"] = "closed" if error.errno == errno.ECONNREFUSED else "error"
            result["error"] = str(error)
        if result["state"] == "open" and probe:
            try:
                if HINTS.get(port) == "http":
                    host = f"[{ip}]" if family == socket.AF_INET6 else ip
                    sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode("ascii"))
                banner = sock.recv(1024).decode("utf-8", errors="replace")
                result["banner"] = banner
                if banner.startswith("SSH-"):
                    result["service"] = "ssh"
                elif banner.startswith("HTTP/"):
                    result["service"] = "http"
                    result["findings"].append({"severity": "info", "id": "cleartext-http",
                        "detail": "HTTP observado sin TLS; revisar si transporta información sensible."})
                elif banner.startswith("220") and "ftp" in banner.lower():
                    result["service"] = "ftp"
                    result["findings"].append({"severity": "info", "id": "ftp-banner",
                        "detail": "Banner FTP observado; verificar uso de TLS antes de enviar credenciales."})
            except (OSError, TimeoutError) as error:
                result["probe_error"] = str(error)
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


def report_html(report):
    rows = []
    for entry in report["results"]:
        cells = [entry["ip"], entry["port"], entry["state"], entry["service"],
                 entry["service_hint"], entry.get("banner", ""),
                 "; ".join(f["detail"] for f in entry["findings"])]
        rows.append("<tr>" + "".join(f"<td>{html.escape(str(value))}</td>" for value in cells) + "</tr>")
    return """<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Informe de reconocimiento</title><style>body{font:15px system-ui;background:#111923;color:#edf3fa;margin:32px}table{border-collapse:collapse;width:100%}td,th{padding:12px;border:1px solid #425367;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere}th{background:#20374a}</style>
<h1>Reconocimiento TCP</h1><p>Los nombres por puerto son orientativos. Un puerto abierto no demuestra una vulnerabilidad.</p>
<table><thead><tr><th>IP</th><th>Puerto</th><th>Estado</th><th>Servicio observado</th><th>Indicio por puerto</th><th>Respuesta</th><th>Observaciones</th></tr></thead><tbody>""" + "".join(rows) + "</tbody></table></html>"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("targets", help="IP o CIDR, separados por coma; sin nombres DNS")
    parser.add_argument("--scope", action="append", default=None, help="CIDR autorizado; repetible. Predeterminado: loopback")
    parser.add_argument("--ports", default="22,80,443,2222,3001-3003,5005,5601,9200")
    parser.add_argument("--timeout", type=float, default=1)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--probe", action="store_true", help="Leer banners; enviar HEAD a puertos HTTP conocidos")
    parser.add_argument("--output", type=Path, default=Path("reports/scan"))
    args = parser.parse_args(argv)
    try:
        if not 0.05 <= args.timeout <= 10 or not 1 <= args.workers <= 128:
            raise ValueError("Timeout 0.05..10 segundos; workers 1..128")
        ips = parse_targets(args.targets, args.scope or ["127.0.0.0/8", "::1/128"])
        ports = parse_ports(args.ports)
        if len(ips) * len(ports) > 65536:
            raise ValueError("Máximo 65536 conexiones por ejecución")
    except ValueError as error:
        parser.error(str(error))
    jobs = [(ip, port) for ip in ips for port in ports]
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(executor.map(lambda job: scan_port(*job, args.timeout, args.probe), jobs))
    report = {"schema_version": 1, "started_at": started,
              "finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
              "scope": args.scope or ["127.0.0.0/8", "::1/128"], "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.with_suffix(".json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    args.output.with_suffix(".html").write_text(report_html(report), encoding="utf-8")
    print(f"{len(results)} conexiones; {sum(r['state'] == 'open' for r in results)} puertos abiertos. Informes: {args.output}.json/.html")


if __name__ == "__main__":
    main()
