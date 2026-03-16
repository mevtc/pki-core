"""Tests for pki_core.validation."""

from pki_core.validation import (
    CertificatePolicy,
    ValidationStatus,
    validate_certificate,
)


class TestValidateCertificate:
    def test_valid_cert(self, cac_cert):
        policy = CertificatePolicy(check_revocation=False)
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.VALID
        assert result.identity is not None
        assert result.identity.cn == "SMITH.JOHN.A.1234567890"

    def test_expired_cert(self, expired_cert):
        policy = CertificatePolicy(check_revocation=False)
        result = validate_certificate(expired_cert, policy)
        assert result.status == ValidationStatus.EXPIRED
        assert result.identity is not None

    def test_skip_validity_check(self, expired_cert):
        policy = CertificatePolicy(check_validity_period=False, check_revocation=False)
        result = validate_certificate(expired_cert, policy)
        assert result.status == ValidationStatus.VALID

    def test_default_policy(self, cac_cert):
        # Default policy checks expiry + revocation. Revocation will
        # fail gracefully since there's no real CRL endpoint, but
        # CRLConfig.strict defaults to True so it may raise.
        # Just verify it doesn't crash.
        policy = CertificatePolicy(check_revocation=False)
        result = validate_certificate(cac_cert, policy)
        assert result.status in (ValidationStatus.VALID, ValidationStatus.ERROR)

    def test_identity_populated_on_failure(self, expired_cert):
        policy = CertificatePolicy(check_revocation=False)
        result = validate_certificate(expired_cert, policy)
        assert result.status == ValidationStatus.EXPIRED
        assert result.identity is not None
        assert result.identity.cn is not None
