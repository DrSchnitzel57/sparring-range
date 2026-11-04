"""The replica CA: one per installation, certs that actually verify.

No trust store is mocked here: a certificate is checked against the CA with
`verification.verify` the moment it is issued, because "TLS verify enabled"
in a check is only honest when the CA chain really validates.
"""
from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from srplatform.labs.pki import LabPKI, pki_directory


def _trust(pki: LabPKI):
    ca = x509.load_pem_x509_certificate(pki.trust_pem())
    return ca


def test_ca_is_created_once_and_reused_bytes_for_bytes(tmp_path):
    pki = LabPKI(tmp_path / "pki")
    pki.ensure_ca()
    first = (tmp_path / "pki" / "ca.crt").read_bytes()
    pki.ensure_ca()
    assert (tmp_path / "pki" / "ca.crt").read_bytes() == first
    assert (tmp_path / "pki" / "ca.key").stat().st_mode & 0o077 == 0


def test_issued_certificate_chains_to_the_ca_and_covers_its_sans(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.verification import PolicyBuilder, Store

    pki = LabPKI(tmp_path / "pki")
    issued = pki.issue("shop.underpressure.local",
                       ["shop.underpressure.local", "www.shop.underpressure.local"])
    cert = x509.load_pem_x509_certificate(issued.certificate_pem)
    names = {n for n in cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)}
    assert names == {"shop.underpressure.local", "www.shop.underpressure.local"}
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == \
        "shop.underpressure.local"

    # real chain validation, not a string comparison
    store = Store([_trust(pki)])
    verifier = PolicyBuilder().store(store).build_server_verifier(
        x509.DNSName("shop.underpressure.local"))
    key = serialization.load_pem_private_key(issued.key_pem, password=None)
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    verifier.verify(cert, [])
    del store


def test_same_request_reuses_the_certificate_but_new_sans_reissue(tmp_path):
    pki = LabPKI(tmp_path / "pki")
    a = pki.issue("mail.underpressure.local", ["mail.underpressure.local"])
    b = pki.issue("mail.underpressure.local", ["mail.underpressure.local"])
    assert a.certificate_pem == b.certificate_pem
    c = pki.issue("mail.underpressure.local",
                  ["mail.underpressure.local", "webmail.underpressure.local"])
    assert c.certificate_pem != a.certificate_pem


def test_a_certificate_from_another_ca_does_not_verify(tmp_path):
    from cryptography.x509.verification import PolicyBuilder, Store
    import pytest
    from cryptography.exceptions import InvalidSignature

    pki = LabPKI(tmp_path / "pki")
    other = LabPKI(tmp_path / "other")
    issued = pki.issue("ecomm.underpressure.local",
                       ["ecomm.underpressure.local"])
    cert = x509.load_pem_x509_certificate(issued.certificate_pem)
    verifier = PolicyBuilder().store(Store([_trust(other)])).build_server_verifier(
        x509.DNSName("ecomm.underpressure.local"))
    with pytest.raises(Exception) as excinfo:
        verifier.verify(cert, [])
    assert excinfo.value is not None


def test_pki_directory_sits_beside_the_controller_state():
    class S:
        safety_state_file = "/var/lib/sparring-range/state/controller/safety_state.json"

    assert str(pki_directory(S())) == "/var/lib/sparring-range/state/controller/pki"
