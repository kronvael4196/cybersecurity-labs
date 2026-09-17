"""Offline scanner. Exit 0 clean, 1 findings, 2 incomplete scan/configuration error.

No matched values or source lines are ever included in output.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def scan(root, rules_file=None):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Se requiere un directorio")
    config = json.loads(Path(rules_file or Path(__file__).with_name("rules.json")).read_text(encoding="utf-8"))
    rules = [(rule, re.compile(rule["pattern"])) for rule in config["rules"]]
    paths = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in config["exclude_dirs"] and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if not path.is_symlink() and name not in config["exclude_files"] and path.suffix.lower() not in config["exclude_suffixes"]:
                paths.append(path)
    ignored = set()
    try:
        result = subprocess.run(["git", "-C", str(root), "check-ignore", "--stdin", "-z"],
            input=b"\0".join(os.fsencode(p) for p in paths) + b"\0", capture_output=True, timeout=30)
        if result.returncode in (0, 1):
            ignored = {os.fsdecode(p) for p in result.stdout.split(b"\0") if p}
        elif (root / ".git").exists():
            raise ValueError("Git no pudo evaluar las exclusiones")
    except FileNotFoundError:
        if (root / ".git").exists():
            raise ValueError("Git es necesario para evaluar .gitignore") from None
    findings, reviewed = [], 0
    for path in paths:
        if str(path) in ignored:
            continue
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError("Archivo de texto potencial demasiado grande: " + str(path.relative_to(root)))
        raw = path.read_bytes()
        if b"\0" in raw[:4096]:
            continue
        text = raw.decode("utf-8", errors="replace")
        reviewed += 1
        for number, line in enumerate(text.splitlines(), 1):
            # Explicit, line-local fixture exemption; a reason is mandatory.
            if re.search(r"# secret-scan: allow -- \S.{5,}", line):
                continue
            for rule, pattern in rules:
                for match in pattern.finditer(line):
                    value = match.group(rule.get("value_group", 0))
                    if rule.get("value_group") and any(value.lower().startswith(prefix) for prefix in config["placeholder_prefixes"]):
                        continue
                    findings.append({"path": path.relative_to(root).as_posix(), "line": number, "rule": rule["id"]})
                    break
    return {"files_scanned": reviewed, "findings": findings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--rules", type=Path)
    args = parser.parse_args(argv)
    try:
        report = scan(args.root, args.rules)
    except (OSError, ValueError, re.error, KeyError, subprocess.SubprocessError):
        print(json.dumps({"error": "Escaneo incompleto; revisa ruta, permisos, Git y rules.json"}))
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
