"""Exercise a running local PKI through HTTP; issue disposable identities and revoke them."""
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
import uuid

BASE = os.getenv("PKI_BASE_URL", "http://127.0.0.1:5005")


def request(path, token=None, data=None, content_type=None, expected=200):
    headers = {}
    if token:
        headers["X-Admin-Token"] = token
    if content_type:
        headers["Content-Type"] = content_type
    req = urllib.request.Request(BASE + path, data=data, headers=headers)
    try:
        response = urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as error:
        if error.code != expected:
            raise RuntimeError(f"{path}: HTTP {error.code}; esperado {expected}") from error
        return error.read(), error.headers
    with response:
        if response.status != expected:
            raise RuntimeError(f"{path}: HTTP {response.status}; esperado {expected}")
        return response.read(), response.headers


def multipart(fields, files):
    boundary = uuid.uuid4().hex
    body = bytearray()
    for name, value in fields.items():
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    for name, (filename, data) in files.items():
        body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode())
        body.extend(data)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode())
    return bytes(body), f"multipart/form-data; boundary={boundary}"


def main():
    env = dict(line.split("=", 1) for line in (Path(__file__).resolve().parent / ".env").read_text().splitlines()
               if line and not line.startswith("#"))
    token = env["PKI_ADMIN_TOKEN"]
    request("/health")
    request("/api/certificates", expected=401)
    for algorithm in ("ECC", "RSA"):
        password = uuid.uuid4().hex
        bundle, headers = request("/api/certificates", token,
            json.dumps({"name": f"Prueba integral {algorithm}", "algorithm": algorithm, "days": 1, "password": password}).encode(),
            "application/json")
        serial = headers["X-Certificate-Serial"]
        try:
            payload, kind = multipart({"password": password}, {"file": ("test.txt", b"prueba local"), "p12": ("test.p12", bundle)})
            signature, _ = request("/api/sign", token, payload, kind)
            payload, kind = multipart({}, {"file": ("test.txt", b"prueba local"), "signature": ("signature.json", signature)})
            verified, _ = request("/api/verify", token, payload, kind)
            if not json.loads(verified)["valid"]:
                raise RuntimeError("La firma original no es válida")
            modified, modified_kind = multipart({}, {"file": ("test.txt", b"modificado"), "signature": ("signature.json", signature)})
            request("/api/verify", token, modified, modified_kind, expected=400)
        finally:
            request(f"/api/certificates/{serial}/revoke", token, b'{"reason":"Fin de prueba integral"}', "application/json")
        request("/api/verify", token, payload, kind, expected=400)
        print(f"{algorithm}: emisión, firma, verificación, manipulación y revocación OK")
    print("Prueba HTTP integral OK. Las dos identidades de prueba quedaron revocadas.")


if __name__ == "__main__":
    main()
