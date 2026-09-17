"""Compatibility entry point: run all nine projects through the pytest runner."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.exit(subprocess.call([sys.executable, str(ROOT / "scripts/pytest_all.py")]))
