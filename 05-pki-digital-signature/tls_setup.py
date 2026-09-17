"""Issue a localhost server certificate from this lab's own CA; keep the CA key out of Nginx."""
import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pki import PKI


def issue_tls(authority, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    os.chmod(output, 0o700)
    now = dt.datetime.now(dt.timezone.utc)
    if not authority.ca.not_valid_before_utc <= now < authority.ca.not_valid_after_utc:
        raise ValueError("La CA no está vigente")
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(authority.ca.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(min(now + dt.timedelta(days=30), authority.ca.not_valid_after_utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(authority.key.public_key()), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                 x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .sign(authority.key, hashes.SHA256()))
    key_path = output / "server.key"
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    (output / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (output / "ca.pem").write_bytes(authority.ca.public_bytes(serialization.Encoding.PEM))
    print("Certificado TLS localhost emitido por la CA local; clave privada excluida de Git.")
    return cert


if __name__ == "__main__":
    from app import load_local_env
    load_local_env()
    base = Path(__file__).resolve().parent
    authority = PKI(os.getenv("PKI_DATA_DIR", str(base / "data")), os.environ["PKI_CA_PASSWORD"])
    issue_tls(authority, os.getenv("PKI_TLS_DIR", str(base / "tls")))
