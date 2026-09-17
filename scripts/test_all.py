"""Execute each independent project's unit tests with the selected Python interpreter."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROJECTS = ["01-mini-siem", "02-vulnerable-home-lab/lessons", "03-network-scanner",
            "04-vpn-traffic-monitor", "05-pki-digital-signature"]
failed = []
for project in PROJECTS:
    print(f"\nProyecto: {project}", flush=True)
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT / project)
    if result.returncode:
        failed.append(project)
if failed:
    sys.exit("Fallaron: " + ", ".join(failed))
print("\nTodas las suites finalizaron correctamente.")
