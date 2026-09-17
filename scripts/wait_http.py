import argparse
import ssl
import time
import urllib.error
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("url")
parser.add_argument("--ca")
parser.add_argument("--seconds", type=int, default=180)
args = parser.parse_args()
context = ssl.create_default_context(cafile=args.ca) if args.ca else None
deadline = time.monotonic() + args.seconds
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen(args.url, timeout=5, context=context) as response:
            if response.status == 200:
                print(f"Disponible: {args.url}")
                break
    except (urllib.error.URLError, TimeoutError):
        time.sleep(2)
else:
    raise SystemExit(f"No disponible tras {args.seconds}s: {args.url}")
