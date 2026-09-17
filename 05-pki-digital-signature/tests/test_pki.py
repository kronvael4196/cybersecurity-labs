import copy
import datetime as dt
import io
import secrets
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from app import create_app
from pki import PKI

PASSWORD = secrets.token_urlsafe(24)
CA_PASSWORD = secrets.token_urlsafe(32)
TOKEN = "test-token-" + "x" * 40


class PKITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.app = create_app({"TESTING": True, "PKI_DATA_DIR": cls.temp.name,
                              "PKI_CA_PASSWORD": CA_PASSWORD, "PKI_ADMIN_TOKEN": TOKEN})
        cls.pki = cls.app.extensions["pki"]
        cls.bundle, cls.serial = cls.pki.issue("Analista", "ECC", 30, PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_ecc_roundtrip(self):
        signature = self.pki.sign(b"documento", self.bundle, PASSWORD)
        self.assertTrue(self.pki.verify(b"documento", signature)["valid"])
        self.assertEqual(signature["algorithm"], "ECDSA-SHA256")

    def test_rsa_roundtrip(self):
        bundle, _ = self.pki.issue("RSA", "RSA", 1, PASSWORD)
        signature = self.pki.sign(b"rsa", bundle, PASSWORD)
        self.assertTrue(self.pki.verify(b"rsa", signature)["valid"])
        self.assertEqual(signature["algorithm"], "RSA-PSS-SHA256")

    def test_tampered_file_and_algorithm(self):
        package = self.pki.sign(b"original", self.bundle, PASSWORD)
        with self.assertRaisesRegex(ValueError, "Firma inválida"):
            self.pki.verify(b"modificado", package)
        altered = copy.deepcopy(package)
        altered["algorithm"] = "RSA-PSS-SHA256"
        with self.assertRaisesRegex(ValueError, "Algoritmo incompatible"):
            self.pki.verify(b"original", altered)

    def test_bad_password(self):
        with self.assertRaisesRegex(ValueError, "contraseña inválidos"):
            self.pki.sign(b"file", self.bundle, "incorrecta")

    def test_revocation_and_signed_crl(self):
        bundle, serial = self.pki.issue("Revocar", "ECC", 1, PASSWORD)
        package = self.pki.sign(b"file", bundle, PASSWORD)
        self.pki.revoke(serial)
        self.pki.revoke(serial)  # idempotent
        with self.assertRaisesRegex(ValueError, "revocado"):
            self.pki.verify(b"file", package)
        with self.assertRaisesRegex(ValueError, "revocado"):
            self.pki.sign(b"file", bundle, PASSWORD)
        crl = self.pki.crl()
        self.assertTrue(crl.is_signature_valid(self.pki.ca.public_key()))
        self.assertIsNotNone(crl.get_revoked_certificate_by_serial_number(int(serial, 16)))

    def test_expired_certificate(self):
        _, cert, _ = pkcs12.load_key_and_certificates(self.bundle, PASSWORD.encode())
        with self.assertRaisesRegex(ValueError, "caducado"):
            self.pki.validate(cert, now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=31))

    def test_foreign_ca_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            foreign = PKI(folder, CA_PASSWORD)
            bundle, _ = foreign.issue("Ajeno", "ECC", 1, PASSWORD)
            package = foreign.sign(b"file", bundle, PASSWORD)
            with self.assertRaisesRegex(ValueError, "CA local"):
                self.pki.verify(b"file", package)

    def test_restart_preserves_registry(self):
        restarted = PKI(self.temp.name, CA_PASSWORD)
        self.assertEqual(restarted.ca.public_bytes(serialization.Encoding.PEM), self.pki.ca.public_bytes(serialization.Encoding.PEM))
        self.assertTrue(any(item["serial"] == self.serial for item in restarted.certificates()))
        with self.assertRaises(ValueError):
            PKI(self.temp.name, "wrong-ca-password-long")

    def test_api_requires_token(self):
        client = self.app.test_client()
        self.assertEqual(client.get("/api/certificates").status_code, 401)
        self.assertEqual(client.post("/api/certificates", json={}).status_code, 401)
        self.assertEqual(client.get("/api/certificates", headers={"X-Admin-Token": TOKEN}).status_code, 200)
        self.assertEqual(client.get("/health").status_code, 200)

    def test_api_issue_sign_verify_revoke(self):
        client = self.app.test_client()
        headers = {"X-Admin-Token": TOKEN}
        issued = client.post("/api/certificates", headers=headers,
                             json={"name": "API", "algorithm": "ECC", "days": 1, "password": PASSWORD})
        self.assertEqual(issued.status_code, 200)
        signed = client.post("/api/sign", headers=headers, data={"file": (io.BytesIO(b"hello"), "hello.txt"),
                     "p12": (io.BytesIO(issued.data), "identity.p12"), "password": PASSWORD})
        self.assertEqual(signed.status_code, 200)
        verified = client.post("/api/verify", headers=headers, data={"file": (io.BytesIO(b"hello"), "hello.txt"),
                             "signature": (io.BytesIO(signed.data), "signature.json")})
        self.assertTrue(verified.json["valid"])
        response = client.post(f"/api/certificates/{issued.headers['X-Certificate-Serial']}/revoke", headers=headers, json={})
        self.assertEqual(response.status_code, 200)

    def test_invalid_payloads(self):
        client = self.app.test_client()
        headers = {"X-Admin-Token": TOKEN}
        self.assertEqual(client.post("/api/certificates", headers=headers, json=[]).status_code, 400)
        self.assertEqual(client.post("/api/certificates", headers=headers, json={}).status_code, 400)
        self.assertEqual(client.post("/api/sign", headers=headers, data={}).status_code, 400)
        for package in (None, {}, {"version": 1, "certificate": 22}):
            with self.assertRaises(ValueError):
                self.pki.verify(b"file", package)


if __name__ == "__main__":
    unittest.main()
