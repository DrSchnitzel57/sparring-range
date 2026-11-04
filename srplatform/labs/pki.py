"""The replica's own certificate authority for HTTPS services.

`verify_tls_against_lab_ca` is a REAL check only if there is a CA the scoring
vantage trusts and service certificates it signed. Nothing here is the
competition's material: the CA is generated once per appliance installation,
under the controller's state directory, and every certificate is issued on
demand (idempotent — the same name + SANs yield the same stored artifact, so
a reset does not churn the vantage's trust).

Why a file-backed CA and not a secret in the store: service certificates
carry no authority beyond this replica's TLS, and the CA KEY must stay out of
every member-visible surface. It lives in the state directory the controller
identity owns (0600); guests receive only certificates and the public CA.
"""
from __future__ import annotations

import datetime
import ipaddress
import pathlib
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_COMMON_NAME = "sparring-range replica lab CA"
CA_VALID_DAYS = 730
CERT_VALID_DAYS = 397    # Apple/Safari limit; also the browser-facing limit


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _pem_key(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def _write(path: pathlib.Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = path.stat().st_mode if path.exists() else None
    path.write_bytes(data)
    path.chmod(mode)  # explicit; umask must never decide a key's privacy
    del flags


@dataclass(frozen=True)
class Issued:
    certificate_pem: bytes
    key_pem: bytes


class LabPKI:
    """One CA directory: `ca.crt` + `ca.key` (0600) + `issued/<cn>.crt|key`."""

    def __init__(self, directory: pathlib.Path):
        self.directory = pathlib.Path(directory)

    # ------------------------------------------------------------- CA

    def ensure_ca(self) -> None:
        """Create the CA once. An existing pair is REUSED verbatim (a changed
        CA would invalidate every certificate already deployed)."""
        cert = self.directory / "ca.crt"
        key = self.directory / "ca.key"
        if cert.is_file() and key.is_file():
            return
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                             CA_COMMON_NAME)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=CA_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0),
                           critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                ca_key.public_key()), critical=False))
        cert_obj = builder.sign(ca_key, hashes.SHA256())
        _write(key, _pem_key(ca_key))
        _write(cert, _pem_cert(cert_obj), mode=0o644)

    def trust_pem(self) -> bytes:
        self.ensure_ca()
        return (self.directory / "ca.crt").read_bytes()

    # ------------------------------------------------------- issuance

    def issue(self, common_name: str, sans: list[str],
              days: int = CERT_VALID_DAYS) -> Issued:
        """Issue (or reuse) a certificate for `common_name` covering `sans`.

        Reuse is keyed on the requested SANs: if the stored certificate covers
        exactly those names and is still valid, it is returned unchanged; any
        change re-issues (store certificates are cheap, trust is not).
        """
        self.ensure_ca()
        safe = common_name.replace("*", "wildcard").replace("/", "_")
        cert_path = self.directory / "issued" / f"{safe}.crt"
        key_path = self.directory / "issued" / f"{safe}.key"
        wanted = sorted({str(s) for s in sans} | {common_name})
        if cert_path.is_file() and key_path.is_file():
            existing = x509.load_pem_x509_certificate(cert_path.read_bytes())
            stored = set()
            try:
                san = existing.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName).value
                stored = {str(n) for n in san.get_values_for_type(x509.DNSName)}
                stored |= {str(n) for n in san.get_values_for_type(x509.IPAddress)}
            except x509.ExtensionNotFound:  # pragma: no cover — ours always has
                stored = set()
            if stored == set(wanted) and (
                    existing.not_valid_after_utc
                    - datetime.datetime.now(datetime.timezone.utc)
                    ).days > 30:
                return Issued(cert_path.read_bytes(), key_path.read_bytes())

        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = x509.load_pem_x509_certificate(
            (self.directory / "ca.crt").read_bytes())
        ca_key = serialization.load_pem_private_key(
            (self.directory / "ca.key").read_bytes(), password=None)
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(n))
                 if _is_ip(n) else x509.DNSName(n) for n in wanted]),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(
                leaf_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False))
        leaf = builder.sign(ca_key, hashes.SHA256())
        _write(key_path, _pem_key(leaf_key))
        _write(cert_path, _pem_cert(leaf), mode=0o644)
        return Issued(cert_path.read_bytes(), key_path.read_bytes())


def pki_directory(settings) -> pathlib.Path:
    """Where the CA lives: beside the controller's own state. The controller
    identity owns it; guests never see the key."""
    state = pathlib.Path(str(settings.safety_state_file))
    #: <state>/controller/safety_state.json -> <state>/controller/pki
    return state.parent / "pki"
