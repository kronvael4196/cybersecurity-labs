"""Summarize packet captures with TShark (Wireshark CLI)."""
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import subprocess

FIELDS = ["frame.number", "frame.len", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
          "_ws.col.Protocol", "tcp.dstport", "udp.dstport", "http.request.method", "http.host"]


def summarize(text):
    protocols, connections = Counter(), Counter()
    http, packet_count, byte_count = [], 0, 0
    for row in csv.reader(io.StringIO(text), delimiter="\t"):
        if not row:
            continue
        row += [""] * (len(FIELDS) - len(row))
        packet_count += 1
        byte_count += int(row[1] or 0)
        protocols[row[6] or "unknown"] += 1
        source, destination = row[2] or row[4], row[3] or row[5]
        if source and destination:
            connections[(source, destination, row[7] or row[8])] += 1
        if row[9]:
            http.append({"frame": row[0], "source": source, "destination": destination,
                         "method": row[9], "host": row[10], "finding": "HTTP visible sin TLS en esta interfaz"})
    return {"packet_count": packet_count, "captured_bytes": byte_count,
            "protocols": dict(protocols), "connections": [
                {"source": key[0], "destination": key[1], "destination_port": key[2], "packets": count}
                for key, count in connections.most_common()], "cleartext_http": http}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--output", type=Path, default=Path("reports/traffic.json"))
    args = parser.parse_args()
    command = ["tshark", "-n", "-r", str(args.pcap), "-T", "fields", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=f"]
    for field in FIELDS:
        command += ["-e", field]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)
    report = summarize(result.stdout)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{report['packet_count']} paquetes; {len(report['cleartext_http'])} peticiones HTTP. Informe: {args.output}")


if __name__ == "__main__":
    main()
