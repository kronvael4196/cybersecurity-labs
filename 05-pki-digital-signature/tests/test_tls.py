import ipaddress
from pathlib import Path
import tempfile
import unittest

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
