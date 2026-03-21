"""Tests for pki.core.revocation — pluggable revocation checking strategies."""

import pytest

from pki.core.crl import CRLConfig
from pki.core.revocation import (
    CRL,
    OCSP,
    CRLCheck,
    OCSPCheck,
    RevocationCheck,
    RevocationPolicy,
    RevocationResult,
    run_revocation_checks,
)
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate

# ---------------------------------------------------------------------------
# Verify ABC enforcement
# ---------------------------------------------------------------------------


class TestRevocationCheckABC:
    def test_cannot_instantiate_abc(self):
        """RevocationCheck is abstract and cannot be instantiated directly."""
        with pytest.raises(TypeError):
            RevocationCheck()

    def test_subclass_must_implement_check(self):
        """Subclass that doesn't implement check() raises TypeError."""

        class IncompleteCheck(RevocationCheck):
            pass

        with pytest.raises(TypeError):
            IncompleteCheck()

    def test_custom_subclass_works(self):
        """A properly implemented subclass can be instantiated and called."""

        class AlwaysGood(RevocationCheck):
            def check(self, cert, policy):
                return RevocationResult.GOOD, "always good"

        strategy = AlwaysGood()
        result, detail = strategy.check(None, RevocationPolicy())
        assert result == RevocationResult.GOOD
        assert detail == "always good"


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------


class TestSingletons:
    def test_crl_is_crl_check(self):
        assert isinstance(CRL, CRLCheck)

    def test_ocsp_is_ocsp_check(self):
        assert isinstance(OCSP, OCSPCheck)

    def test_repr(self):
        assert repr(CRL) == "CRL"
        assert repr(OCSP) == "OCSP"


# ---------------------------------------------------------------------------
# run_revocation_checks
# ---------------------------------------------------------------------------


class _StubCheck(RevocationCheck):
    """Test stub that returns a fixed result."""

    def __init__(self, result: RevocationResult, detail: str = "stub"):
        self._result = result
        self._detail = detail

    def check(self, cert, policy):
        return self._result, self._detail


class TestRunRevocationChecks:
    def test_good_stops_immediately(self):
        pol = RevocationPolicy(
            checks=[_StubCheck(RevocationResult.GOOD, "ok"), _StubCheck(RevocationResult.REVOKED)]
        )
        result, detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.GOOD
        assert detail == "ok"

    def test_revoked_stops_immediately(self):
        pol = RevocationPolicy(
            checks=[
                _StubCheck(RevocationResult.REVOKED, "revoked!"),
                _StubCheck(RevocationResult.GOOD),
            ]
        )
        result, _detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.REVOKED

    def test_unavailable_falls_through(self):
        pol = RevocationPolicy(
            checks=[
                _StubCheck(RevocationResult.UNAVAILABLE, "no CRL"),
                _StubCheck(RevocationResult.GOOD, "OCSP ok"),
            ]
        )
        result, detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.GOOD
        assert detail == "OCSP ok"

    def test_all_unavailable_strict(self):
        pol = RevocationPolicy(
            checks=[
                _StubCheck(RevocationResult.UNAVAILABLE, "no CRL"),
                _StubCheck(RevocationResult.UNAVAILABLE, "no OCSP"),
            ],
            strict=True,
        )
        result, detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.UNAVAILABLE
        assert "strict" in detail.lower()

    def test_all_unavailable_non_strict(self):
        pol = RevocationPolicy(
            checks=[
                _StubCheck(RevocationResult.UNAVAILABLE, "no CRL"),
                _StubCheck(RevocationResult.UNAVAILABLE, "no OCSP"),
            ],
            strict=False,
        )
        result, detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.GOOD
        assert "non-strict" in detail.lower()

    def test_empty_checks_strict(self):
        pol = RevocationPolicy(checks=[], strict=True)
        result, _detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.UNAVAILABLE

    def test_empty_checks_non_strict(self):
        pol = RevocationPolicy(checks=[], strict=False)
        result, _detail = run_revocation_checks(pol, None)
        assert result == RevocationResult.GOOD


# ---------------------------------------------------------------------------
# CRLCheck integration
# ---------------------------------------------------------------------------


class TestCRLCheck:
    def test_delegates_to_crl_module(self, cac_cert, ca_cert, test_crl, tmp_path):
        """CRLCheck wraps crl.check_revocation — revoked cert returns REVOKED."""
        import hashlib

        from cryptography.hazmat.primitives.serialization import Encoding

        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl.public_bytes(Encoding.DER))

        pol = RevocationPolicy(
            checks=(CRL,),
            issuer_certs=[ca_cert],
            crl_config=CRLConfig(cache_dir=str(tmp_path), strict=True),
        )
        result, detail = CRL.check(cac_cert, pol)
        assert result == RevocationResult.REVOKED
        assert "revoked" in detail.lower()


# ---------------------------------------------------------------------------
# OCSPCheck — unit tests (no real OCSP responder)
# ---------------------------------------------------------------------------


class TestOCSPCheck:
    def test_no_aia_returns_unavailable(self, cac_cert):
        """Cert without AIA extension → UNAVAILABLE."""
        pol = RevocationPolicy(issuer_certs=[None])
        result, detail = OCSP.check(cac_cert, pol)
        assert result == RevocationResult.UNAVAILABLE
        assert "AIA" in detail

    def test_no_issuer_certs_returns_unavailable(self, cac_cert):
        """Without issuer certs, OCSP can't build a request.

        cac_cert has no AIA extension, so it hits that check first.
        Both cases should return UNAVAILABLE.
        """
        pol = RevocationPolicy(issuer_certs=None)
        result, _detail = OCSP.check(cac_cert, pol)
        assert result == RevocationResult.UNAVAILABLE


# ---------------------------------------------------------------------------
# Pipeline integration — validate_certificate with custom strategies
# ---------------------------------------------------------------------------


class TestValidateCertificateRevocation:
    def test_custom_strategy_good(self, cac_cert):
        """Custom strategy returning GOOD → VALID."""
        policy = CertificatePolicy(
            revocation=RevocationPolicy(checks=(_StubCheck(RevocationResult.GOOD),)),
        )
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.VALID

    def test_custom_strategy_revoked(self, cac_cert):
        """Custom strategy returning REVOKED → REVOKED."""
        policy = CertificatePolicy(
            revocation=RevocationPolicy(
                checks=(_StubCheck(RevocationResult.REVOKED, "revoked by stub"),)
            ),
        )
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.REVOKED
        assert "revoked by stub" in result.error

    def test_fallback_order(self, cac_cert):
        """First check unavailable, second check good → VALID."""
        policy = CertificatePolicy(
            revocation=RevocationPolicy(
                checks=(
                    _StubCheck(RevocationResult.UNAVAILABLE),
                    _StubCheck(RevocationResult.GOOD, "fallback ok"),
                )
            ),
        )
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.VALID

    def test_none_skips_revocation(self, cac_cert):
        """revocation=None → no revocation checking."""
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.VALID
