import ipaddress
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import tempfile
import ssl
import threading
import unittest
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from pki import PKI
from tls_setup import issue_tls


class TLSTests(unittest.TestCase):
    def test_server_certificate_trust_names_and_key(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            authority = PKI(root / "ca", "temporary-ca-password-long")
            cert = issue_tls(authority, root / "tls")
            cert.verify_directly_issued_by(authority.ca)
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("localhost", names.get_values_for_type(x509.DNSName))
            self.assertIn(ipaddress.ip_address("127.0.0.1"), names.get_values_for_type(x509.IPAddress))
            self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            key = serialization.load_pem_private_key((root / "tls/server.key").read_bytes(), password=None)
            self.assertEqual(key.public_key().public_numbers(), cert.public_key().public_numbers())
            self.assertFalse((root / "tls/ca.key").exists())
            class Handler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"verified")
                def log_message(self, *_):
                    pass
            server = HTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / "tls/server.pem", root / "tls/server.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            client_context = ssl.create_default_context(cafile=str(root / "tls/ca.pem"))
            client_context.verify_flags |= ssl.VERIFY_X509_STRICT
            try:
                with urllib.request.urlopen(f"https://127.0.0.1:{server.server_port}", context=client_context, timeout=5) as response:
                    self.assertEqual(response.read(), b"verified")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(5)
