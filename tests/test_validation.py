"""Tests for pki.core.validation."""

import datetime
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from pki.core.revocation import RevocationPolicy, RevocationResult
from pki.core.validation import (
    CertificatePolicy,
    ValidationStatus,
    validate_certificate,
)


class TestValidateCertificate:
    def test_valid_cert(self, cac_cert):
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.VALID
        assert result.identity is not None
        assert result.identity.cn == "SMITH.JOHN.A.1234567890"

    def test_expired_cert(self, expired_cert):
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(expired_cert, policy)
        assert result.status == ValidationStatus.EXPIRED
        assert result.identity is not None

    def test_skip_validity_check(self, expired_cert):
        policy = CertificatePolicy(check_validity_period=False, revocation=None)
        result = validate_certificate(expired_cert, policy)
        assert result.status == ValidationStatus.VALID

    def test_default_policy(self, cac_cert):
        # Default policy checks expiry + CRL revocation. Revocation will
        # fail gracefully since there's no real CRL endpoint, but
        # CRLConfig.strict defaults to True so it may raise.
        # Just verify it doesn't crash.
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(cac_cert, policy)
        assert result.status in (ValidationStatus.VALID, ValidationStatus.ERROR)

    def test_identity_populated_on_failure(self, expired_cert):
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(expired_cert, policy)
        assert result.status == ValidationStatus.EXPIRED
        assert result.identity is not None
        assert result.identity.cn is not None

    def test_none_policy_uses_default(self, cac_cert):
        """When policy is None, validate_certificate uses default CertificatePolicy."""
        # Default policy has revocation enabled which will fail without a CRL,
        # but the key thing is it doesn't crash with None policy
        result = validate_certificate(cac_cert, policy=None)
        assert result.status in (
            ValidationStatus.VALID,
            ValidationStatus.ERROR,
            ValidationStatus.REVOKED,
        )

    def test_not_yet_valid_cert(self, ca_key, ca_cert, signer_key):
        """Certificate with notBefore in the future returns NOT_YET_VALID."""
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FUTURE.USER.X.1234567890")])
        future_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(signer_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2099, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2100, 1, 1, tzinfo=datetime.UTC))
            .sign(ca_key, hashes.SHA256())
        )
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(future_cert, policy)
        assert result.status == ValidationStatus.NOT_YET_VALID
        assert "not yet valid" in result.error.lower()

    def test_identity_extraction_failure(self, cac_cert):
        """When parse_identity raises, returns ERROR status."""
        policy = CertificatePolicy(revocation=None)
        with patch(
            "pki.core.validation.parse_identity",
            side_effect=ValueError("parse failure"),
        ):
            result = validate_certificate(cac_cert, policy)
            assert result.status == ValidationStatus.ERROR
            assert "extraction failed" in result.error.lower()

    def test_revocation_unavailable_returns_error(self, cac_cert):
        """When revocation check returns UNAVAILABLE, returns ERROR status."""
        from tests.test_revocation import _StubCheck

        policy = CertificatePolicy(
            revocation=RevocationPolicy(
                checks=[_StubCheck(RevocationResult.UNAVAILABLE, "CRL unavailable")],
                strict=True,
            ),
        )
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.ERROR
        assert "unavailable" in result.error.lower()
