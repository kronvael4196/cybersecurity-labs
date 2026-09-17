"""Run from project root with Docker stack ready and default rule settings."""
import datetime
import subprocess

since = datetime.datetime.now(datetime.timezone.utc).isoformat()
subprocess.run(["docker", "compose", "exec", "-T", "ssh", "python", "/app/demo.py"], check=True)
subprocess.run(["docker", "compose", "exec", "-T", "detector", "python", "app.py", "verify", since], check=True)
