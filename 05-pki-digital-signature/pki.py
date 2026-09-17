"""Local CA, detached signatures and revocation. No third-party trust stores."""
import base64
from contextlib import contextmanager
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

UTC = dt.timezone.utc


class PKI:
    def __init__(self, folder, password):
        if len(password) < 16:
            raise ValueError("La contraseña de la CA debe tener al menos 16 caracteres")
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.db_path = self.folder / "registry.sqlite3"
        key_path, cert_path = self.folder / "ca.key", self.folder / "ca.pem"
        if key_path.exists() != cert_path.exists():
            raise ValueError("CA incompleta: restaura su clave y certificado; no se reemplazará automáticamente")
        if not key_path.exists():
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cybersecurity Labs Local CA")])
            now = dt.datetime.now(UTC)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
                    .not_valid_after(now + dt.timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                    .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                    .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                    .sign(key, hashes.SHA256()))
            encrypted = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.BestAvailableEncryption(password.encode()))
            with key_path.open("xb") as file:
                file.write(encrypted)
            os.chmod(key_path, 0o600)
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key = serialization.load_pem_private_key(key_path.read_bytes(), password=password.encode())
        self.ca = x509.load_pem_x509_certificate(cert_path.read_bytes())
        if self.key.public_key().public_numbers() != self.ca.public_key().public_numbers():
            raise ValueError("La clave no corresponde a la CA")
        self.ca.verify_directly_issued_by(self.ca)
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS certificates(serial TEXT PRIMARY KEY, name TEXT NOT NULL, "
                       "algorithm TEXT NOT NULL, pem TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, "
                       "revoked_at TEXT, reason TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time TEXT, action TEXT, serial TEXT)")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def audit(db, action, serial):
        db.execute("INSERT INTO audit(time,action,serial) VALUES(?,?,?)", (dt.datetime.now(UTC).isoformat(), action, serial))

    def issue(self, name, algorithm, days, password):
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 64 or any(ord(c) < 32 for c in name):
            raise ValueError("Nombre requerido: 1 a 64 caracteres sin controles")
        if type(days) is not int or not 1 <= days <= 365:
            raise ValueError("Validez permitida: 1 a 365 días")
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise ValueError("Contraseña PKCS#12: 12 a 128 caracteres")
        if algorithm == "RSA":
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        elif algorithm == "ECC":
            key = ec.generate_private_key(ec.SECP384R1())
        else:
            raise ValueError("Algoritmo permitido: RSA o ECC")
        now = dt.datetime.now(UTC)
        if not self.ca.not_valid_before_utc <= now < self.ca.not_valid_after_utc:
            raise ValueError("CA fuera de su período de validez")
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name.strip())]))
                .issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=1))
                .not_valid_after(min(now + dt.timedelta(days=days), self.ca.not_valid_after_utc))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False)
                .sign(self.key, hashes.SHA256()))
        bundle = pkcs12.serialize_key_and_certificates(name.strip().encode(), key, cert, [self.ca],
                   serialization.BestAvailableEncryption(password.encode()))
        serial = format(cert.serial_number, "x")
        with self.connect() as db:
            db.execute("INSERT INTO certificates VALUES(?,?,?,?,?,?,NULL,NULL)",
                       (serial, name.strip(), algorithm, cert.public_bytes(serialization.Encoding.PEM).decode(),
                        now.isoformat(), cert.not_valid_after_utc.isoformat()))
            self.audit(db, "issue", serial)
        return bundle, serial

    def certificates(self):
        with self.connect() as db:
            return [dict(row) for row in db.execute("SELECT serial,name,algorithm,issued_at,expires_at,revoked_at,reason FROM certificates ORDER BY issued_at DESC")]

    def revoke(self, serial, reason="Revocación solicitada"):
        if not isinstance(reason, str) or not 1 <= len(reason) <= 200:
            raise ValueError("Motivo requerido: 1 a 200 caracteres")
        with self.connect() as db:
            row = db.execute("SELECT revoked_at FROM certificates WHERE serial=?", (serial,)).fetchone()
            if row is None:
                raise ValueError("Certificado desconocido")
            if row["revoked_at"] is None:
                db.execute("UPDATE certificates SET revoked_at=?,reason=? WHERE serial=?",
                           (dt.datetime.now(UTC).isoformat(), reason, serial))
                self.audit(db, "revoke", serial)

    def crl(self):
        now = dt.datetime.now(UTC)
        builder = (x509.CertificateRevocationListBuilder().issuer_name(self.ca.subject)
                   .last_update(now - dt.timedelta(seconds=1)).next_update(now + dt.timedelta(hours=24)))
        with self.connect() as db:
            for row in db.execute("SELECT serial,revoked_at FROM certificates WHERE revoked_at IS NOT NULL"):
                revoked = (x509.RevokedCertificateBuilder().serial_number(int(row["serial"], 16))
                           .revocation_date(dt.datetime.fromisoformat(row["revoked_at"]))
                           .add_extension(x509.CRLReason(x509.ReasonFlags.unspecified), critical=False).build())
                builder = builder.add_revoked_certificate(revoked)
        return builder.sign(self.key, hashes.SHA256())

    def validate(self, cert, now=None):
        now = now or dt.datetime.now(UTC)
        try:
            cert.verify_directly_issued_by(self.ca)
        except (ValueError, TypeError, InvalidSignature) as error:
            raise ValueError("Certificado no emitido por la CA local") from error
        for item in (self.ca, cert):
            if not item.not_valid_before_utc <= now <= item.not_valid_after_utc:
                raise ValueError("Certificado o CA caducado o todavía no válido")
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Se requiere un certificado de usuario, no de CA")
        if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            raise ValueError("El certificado no permite firma digital")
        serial = format(cert.serial_number, "x")
        with self.connect() as db:
            row = db.execute("SELECT pem FROM certificates WHERE serial=?", (serial,)).fetchone()
        if not row or x509.load_pem_x509_certificate(row["pem"].encode()).fingerprint(hashes.SHA256()) != cert.fingerprint(hashes.SHA256()):
            raise ValueError("Certificado no registrado en esta CA")
        crl = self.crl()
        if not crl.is_signature_valid(self.ca.public_key()):
            raise ValueError("Firma CRL inválida")
        if not crl.last_update_utc <= now <= crl.next_update_utc:
            raise ValueError("CRL fuera de su período de validez")
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number):
            raise ValueError("Certificado revocado")
        return serial

    def sign(self, data, bundle, password):
        try:
            key, cert, _ = pkcs12.load_key_and_certificates(bundle, password.encode())
        except ValueError as error:
            raise ValueError("PKCS#12 o contraseña inválidos") from error
        if key is None or cert is None:
            raise ValueError("PKCS#12 sin clave o certificado")
        serial = self.validate(cert)
        if isinstance(key, rsa.RSAPrivateKey):
            signature = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
            algorithm = "RSA-PSS-SHA256"
        elif isinstance(key, ec.EllipticCurvePrivateKey):
            signature = key.sign(data, ec.ECDSA(hashes.SHA256()))
            algorithm = "ECDSA-SHA256"
        else:
            raise ValueError("Tipo de clave no soportado")
        with self.connect() as db:
            self.audit(db, "sign", serial)
        return {"version": 1, "algorithm": algorithm, "sha256": hashlib.sha256(data).hexdigest(),
                "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
                "signature": base64.b64encode(signature).decode()}

    def verify(self, data, package):
        try:
            if not isinstance(package, dict) or package.get("version") != 1:
                raise ValueError("Formato de firma no soportado")
            cert = x509.load_pem_x509_certificate(package["certificate"].encode())
            serial = self.validate(cert)
            signature = base64.b64decode(package["signature"], validate=True)
            key = cert.public_key()
            if package["algorithm"] == "RSA-PSS-SHA256" and isinstance(key, rsa.RSAPublicKey):
                key.verify(signature, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH), hashes.SHA256())
            elif package["algorithm"] == "ECDSA-SHA256" and isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            else:
                raise ValueError("Algoritmo incompatible")
            digest = hashlib.sha256(data).hexdigest()
            if package.get("sha256") != digest:
                raise ValueError("Hash del archivo no coincide")
        except InvalidSignature as error:
            raise ValueError("Firma inválida: el archivo o la firma se modificaron") from error
        except (KeyError, TypeError, AttributeError) as error:
            raise ValueError("Paquete de firma mal formado") from error
        return {"valid": True, "serial": serial, "sha256": digest,
                "subject": cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
                "revocation": "checked", "trust": "local-ca"}
