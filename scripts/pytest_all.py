"""Run projects in separate processes to keep their independent 'app' modules isolated."""
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ["01-mini-siem", "02-vulnerable-home-lab/lessons", "03-network-scanner",
            "04-vpn-traffic-monitor", "05-pki-digital-signature"]


def main():
    output = ROOT / "artifacts/pytest"
    output.mkdir(parents=True, exist_ok=True)
    summary = []
    for project in PROJECTS:
        slug = project.split("/")[0]
        junit = output / f"{slug}.xml"
        command = [sys.executable, "-m", "pytest", "tests", "-v", "--color=no", "-p", "no:cacheprovider",
                   f"--junitxml={junit}", f"--html={output / (slug + '.html')}", "--self-contained-html"]
        result = subprocess.run(command, cwd=ROOT / project, text=True, encoding="utf-8",
                                errors="replace", stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        (output / f"{slug}.txt").write_text(result.stdout, encoding="utf-8")
        print(result.stdout, flush=True)
        suites = ET.parse(junit).getroot().findall("testsuite") if junit.exists() else []
        summary.append({"project": slug, "exit_code": result.returncode,
                        **{key: sum(int(s.get(key, "0")) for s in suites) for key in ("tests", "failures", "errors", "skipped")}})
    (output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return 1 if any(item["exit_code"] for item in summary) else 0


if __name__ == "__main__":
    sys.exit(main())
