"""Tests for pki.core.certificate module."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from pki.core.certificate import (
    CertificateError,
    cert_fingerprint,
    cert_to_pem,
    extract_email,
    extract_san_uuid,
    get_name_attr,
    get_policy_oids,
    is_expired,
    load_certificate,
)


class TestLoadCertificate:
    def test_load_pem(self, cac_cert):
        pem = cac_cert.public_bytes(serialization.Encoding.PEM)
        cert = load_certificate(pem)
        assert cert.serial_number == cac_cert.serial_number

    def test_load_der(self, cac_cert):
        der = cac_cert.public_bytes(serialization.Encoding.DER)
        cert = load_certificate(der)
        assert cert.serial_number == cac_cert.serial_number

    def test_load_garbage_raises(self):
        with pytest.raises(CertificateError):
            load_certificate(b"not a certificate")


class TestGetNameAttr:
    def test_existing_attr(self, cac_cert):
        cn = get_name_attr(cac_cert.subject, NameOID.COMMON_NAME)
        assert cn == "SMITH.JOHN.A.1234567890"

    def test_missing_attr(self, cac_cert):
        result = get_name_attr(cac_cert.subject, NameOID.STATE_OR_PROVINCE_NAME)
        assert result is None


class TestGetPolicyOids:
    def test_cac_policy(self, cac_cert):
        oids = get_policy_oids(cac_cert)
        assert "2.16.840.1.101.2.1.11.19" in oids

    def test_piv_policy(self, piv_cert):
        oids = get_policy_oids(piv_cert)
        assert "2.16.840.1.101.3.2.1.3.13" in oids

    def test_no_policy(self, ca_cert):
        oids = get_policy_oids(ca_cert)
        assert oids == []


class TestExtractEmail:
    def test_from_san(self, cac_cert):
        email = extract_email(cac_cert)
        assert email == "john.smith@mail.mil"

    def test_piv_email(self, piv_cert):
        email = extract_email(piv_cert)
        assert email == "alice.jones@doe.gov"


class TestExtractSanUuid:
    def test_piv_uuid(self, piv_cert):
        uuid = extract_san_uuid(piv_cert)
        assert uuid == "12345678-abcd-ef01-2345-6789abcdef01"

    def test_no_uuid(self, cac_cert):
        uuid = extract_san_uuid(cac_cert)
        assert uuid is None

    def test_malformed_uuid_rejected(self, bad_uuid_cert):
        uuid = extract_san_uuid(bad_uuid_cert)
        assert uuid is None


class TestCertFingerprint:
    def test_returns_hex_string(self, cac_cert):
        fp = cert_fingerprint(cac_cert)
        assert len(fp) == 64  # SHA-256 hex
        assert all(c in "0123456789abcdef" for c in fp)

    def test_deterministic(self, cac_cert):
        assert cert_fingerprint(cac_cert) == cert_fingerprint(cac_cert)


class TestCertToPem:
    def test_returns_pem_string(self, cac_cert):
        pem = cert_to_pem(cac_cert)
        assert pem.startswith("-----BEGIN CERTIFICATE-----")
        assert pem.strip().endswith("-----END CERTIFICATE-----")


class TestIsExpired:
    def test_valid_cert(self, cac_cert):
        assert is_expired(cac_cert) is False

    def test_expired_cert(self, expired_cert):
        assert is_expired(expired_cert) is True


class TestIsNotYetValid:
    def test_future_cert(self, signer_key):
        """A certificate with notBefore in the future."""
        import datetime

        from cryptography import x509 as x509_mod
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID as NameOID_

        subject = x509_mod.Name([x509_mod.NameAttribute(NameOID_.COMMON_NAME, "FUTURE.USER")])
        cert = (
            x509_mod.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(signer_key.public_key())
            .serial_number(x509_mod.random_serial_number())
            .not_valid_before(datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2100, 1, 1, tzinfo=datetime.UTC))
            .sign(signer_key, hashes.SHA256())
        )
        from pki.core.certificate import is_not_yet_valid

        assert is_not_yet_valid(cert) is True

    def test_current_cert_not_premature(self, cac_cert):
        from pki.core.certificate import is_not_yet_valid

        assert is_not_yet_valid(cac_cert) is False
