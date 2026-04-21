"""Tests for pki.core.revocation — pluggable revocation checking strategies."""

import datetime
from unittest.mock import MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from pki.core.certificate import CertificateError
from pki.core.crl import CRLConfig
from pki.core.revocation import (
    CRL,
    OCSP,
    CRLCheck,
    OCSPCheck,
    RevocationCheck,
    RevocationPolicy,
    RevocationResult,
    _find_issuer,
    _get_ocsp_responder_urls,
    _query_ocsp,
    _verify_ocsp_response_signature,
    _verify_signature,
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


# ---------------------------------------------------------------------------
# CRLCheck — UNAVAILABLE path
# ---------------------------------------------------------------------------


class TestCRLCheckUnavailable:
    def test_crl_unavailable_returns_unavailable(self, cac_cert, tmp_path):
        """CRL check that can't fetch returns UNAVAILABLE."""
        import httpx

        pol = RevocationPolicy(
            checks=(CRL,),
            issuer_certs=None,
            crl_config=CRLConfig(cache_dir=str(tmp_path), strict=True),
        )
        with patch("pki.core.crl.httpx.get", side_effect=httpx.ConnectError("refused")):
            result, _detail = CRL.check(cac_cert, pol)
            # CRL raises CertificateError("Could not verify..."), which has no "revoked"
            # so it falls to UNAVAILABLE
            assert result == RevocationResult.UNAVAILABLE


# ---------------------------------------------------------------------------
# OCSP helpers — _get_ocsp_responder_urls, _find_issuer, _query_ocsp
# ---------------------------------------------------------------------------


def _make_cert_with_aia(ca_key, ca_cert, ocsp_url):
    """Create a certificate with an AIA extension pointing to an OCSP responder."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP.TEST.USER")])
    aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(ocsp_url),
            ),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(aia, critical=False)
        .sign(ca_key, hashes.SHA256())
    )


class TestGetOcspResponderUrls:
    def test_cert_with_ocsp_url(self, ca_key, ca_cert):
        """Certificate with AIA OCSP extension returns the URL."""
        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")
        urls = _get_ocsp_responder_urls(cert)
        assert urls == ["http://ocsp.example.com"]

    def test_cert_without_aia(self, ca_cert):
        """Certificate without AIA returns empty list."""
        urls = _get_ocsp_responder_urls(ca_cert)
        assert urls == []

    def test_non_http_url_skipped(self, ca_key, ca_cert):
        """Non-HTTP(S) OCSP URLs are skipped."""
        cert = _make_cert_with_aia(ca_key, ca_cert, "ldap://ocsp.example.com")
        urls = _get_ocsp_responder_urls(cert)
        assert urls == []


class TestFindIssuer:
    def test_finds_matching_issuer(self, cac_cert, ca_cert):
        """Finds the issuer cert when it matches."""
        result = _find_issuer(cac_cert, [ca_cert])
        assert result is not None
        assert result.subject == cac_cert.issuer

    def test_no_match_returns_none(self, cac_cert, wrong_ca_cert):
        """Returns None when no issuer cert matches."""
        result = _find_issuer(cac_cert, [wrong_ca_cert])
        assert result is None

    def test_empty_list_returns_none(self, cac_cert):
        """Returns None for empty issuer list."""
        result = _find_issuer(cac_cert, [])
        assert result is None


class TestQueryOcsp:
    def test_good_response(self, ca_key, ca_cert):
        """OCSP good response returns GOOD."""
        from cryptography.x509 import ocsp

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        # Build a mock OCSP response
        mock_ocsp_resp = MagicMock()
        mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_resp.certificate_status = ocsp.OCSPCertStatus.GOOD

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"fake-ocsp-response"
        mock_http_resp.raise_for_status = MagicMock()

        with (
            patch("pki.core.revocation.httpx.post", return_value=mock_http_resp),
            patch("pki.core.revocation.ocsp.load_der_ocsp_response", return_value=mock_ocsp_resp),
            patch("pki.core.revocation._verify_ocsp_response_signature"),
        ):
            result, detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.GOOD
            assert "good" in detail.lower()

    def test_revoked_response(self, ca_key, ca_cert):
        """OCSP revoked response returns REVOKED."""
        from cryptography.x509 import ocsp

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        mock_ocsp_resp = MagicMock()
        mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_resp.certificate_status = ocsp.OCSPCertStatus.REVOKED

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"fake-ocsp-response"
        mock_http_resp.raise_for_status = MagicMock()

        with (
            patch("pki.core.revocation.httpx.post", return_value=mock_http_resp),
            patch("pki.core.revocation.ocsp.load_der_ocsp_response", return_value=mock_ocsp_resp),
            patch("pki.core.revocation._verify_ocsp_response_signature"),
        ):
            result, _detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.REVOKED

    def test_unknown_status(self, ca_key, ca_cert):
        """OCSP unknown status returns UNAVAILABLE."""
        from cryptography.x509 import ocsp

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        mock_ocsp_resp = MagicMock()
        mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_resp.certificate_status = ocsp.OCSPCertStatus.UNKNOWN

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"fake-ocsp-response"
        mock_http_resp.raise_for_status = MagicMock()

        with (
            patch("pki.core.revocation.httpx.post", return_value=mock_http_resp),
            patch("pki.core.revocation.ocsp.load_der_ocsp_response", return_value=mock_ocsp_resp),
            patch("pki.core.revocation._verify_ocsp_response_signature"),
        ):
            result, detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.UNAVAILABLE
            assert "unknown" in detail.lower()

    def test_network_failure(self, ca_key, ca_cert):
        """Network failure returns UNAVAILABLE."""
        import httpx

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        with patch("pki.core.revocation.httpx.post", side_effect=httpx.ConnectError("refused")):
            result, detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.UNAVAILABLE
            assert "failed" in detail.lower()

    def test_bad_response_parse(self, ca_key, ca_cert):
        """Unparseable OCSP response returns UNAVAILABLE."""
        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"not-a-valid-ocsp-response"
        mock_http_resp.raise_for_status = MagicMock()

        with (
            patch("pki.core.revocation.httpx.post", return_value=mock_http_resp),
            patch(
                "pki.core.revocation.ocsp.load_der_ocsp_response",
                side_effect=ValueError("bad data"),
            ),
        ):
            result, detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.UNAVAILABLE
            assert "parse" in detail.lower()

    def test_non_successful_response_status(self, ca_key, ca_cert):
        """OCSP responder returning non-SUCCESSFUL status returns UNAVAILABLE."""
        from cryptography.x509 import ocsp

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        mock_ocsp_resp = MagicMock()
        mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.UNAUTHORIZED

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"fake"
        mock_http_resp.raise_for_status = MagicMock()

        with (
            patch("pki.core.revocation.httpx.post", return_value=mock_http_resp),
            patch("pki.core.revocation.ocsp.load_der_ocsp_response", return_value=mock_ocsp_resp),
        ):
            result, detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.UNAVAILABLE
            assert "UNAUTHORIZED" in detail


# ---------------------------------------------------------------------------
# OCSPCheck integration — cert with AIA extension
# ---------------------------------------------------------------------------


class TestOCSPCheckWithAIA:
    def test_no_issuer_certs(self, ca_key, ca_cert):
        """OCSP check with no issuer certs returns UNAVAILABLE."""
        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")
        pol = RevocationPolicy(issuer_certs=None)
        result, detail = OCSP.check(cert, pol)
        assert result == RevocationResult.UNAVAILABLE
        assert "issuer" in detail.lower()

    def test_no_matching_issuer(self, ca_key, ca_cert, wrong_ca_cert):
        """OCSP check with non-matching issuer returns UNAVAILABLE."""
        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")
        pol = RevocationPolicy(issuer_certs=[wrong_ca_cert])
        result, detail = OCSP.check(cert, pol)
        assert result == RevocationResult.UNAVAILABLE
        assert "issuer" in detail.lower()

    def test_all_responders_unavailable(self, ca_key, ca_cert):
        """When all OCSP responders fail, returns UNAVAILABLE with count."""
        import httpx

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")
        pol = RevocationPolicy(issuer_certs=[ca_cert])
        with patch("pki.core.revocation.httpx.post", side_effect=httpx.ConnectError("refused")):
            result, detail = OCSP.check(cert, pol)
            assert result == RevocationResult.UNAVAILABLE
            assert "unavailable" in detail.lower()


# ---------------------------------------------------------------------------
# OCSP response signature verification
# ---------------------------------------------------------------------------


class TestVerifySignature:
    def test_rsa_valid(self, ca_key, ca_cert):
        """RSA signature verification succeeds for a valid cert."""
        _verify_signature(
            ca_cert.public_key(),
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            ca_cert.signature_hash_algorithm,
        )

    def test_rsa_invalid(self, ca_cert):
        """RSA signature verification fails with tampered data."""
        from cryptography.exceptions import InvalidSignature

        with pytest.raises(InvalidSignature):
            _verify_signature(
                ca_cert.public_key(),
                ca_cert.signature,
                b"tampered data",
                ca_cert.signature_hash_algorithm,
            )

    def test_ec_valid(self):
        """EC signature verification succeeds."""
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        data = b"test data"
        sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
        _verify_signature(key.public_key(), sig, data, hashes.SHA256())

    def test_ec_invalid(self):
        """EC signature verification fails with wrong data."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric import ec

        key = ec.generate_private_key(ec.SECP256R1())
        sig = key.sign(b"original", ec.ECDSA(hashes.SHA256()))
        with pytest.raises(InvalidSignature):
            _verify_signature(key.public_key(), sig, b"tampered", hashes.SHA256())

    def test_unsupported_key_type(self):
        """Unsupported key type raises CertificateError."""
        mock_key = MagicMock()
        type(mock_key).__name__ = "FakeKey"
        with pytest.raises(CertificateError, match="Unsupported"):
            _verify_signature(mock_key, b"sig", b"data", hashes.SHA256())

    def test_none_hash_defaults_to_sha256(self, ca_key, ca_cert):
        """None hash_algorithm defaults to SHA256."""
        # ca_cert uses SHA256, so verifying with None should work
        _verify_signature(
            ca_cert.public_key(),
            ca_cert.signature,
            ca_cert.tbs_certificate_bytes,
            None,
        )


class TestVerifyOcspResponseSignature:
    def test_direct_issuer_signing(self, ca_key, ca_cert):
        """Response signed by issuer CA directly (no responder certs)."""
        from cryptography.hazmat.primitives.asymmetric import padding

        data = b"ocsp tbs response data"
        sig = ca_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        mock_resp = MagicMock()
        mock_resp.certificates = []
        mock_resp.signature = sig
        mock_resp.tbs_response_bytes = data
        mock_resp.signature_hash_algorithm = hashes.SHA256()

        # Should not raise
        _verify_ocsp_response_signature(mock_resp, ca_cert)

    def test_direct_issuer_signing_bad_sig(self, ca_cert):
        """Bad signature from issuer CA raises CertificateError."""
        mock_resp = MagicMock()
        mock_resp.certificates = []
        mock_resp.signature = b"bad-signature"
        mock_resp.tbs_response_bytes = b"data"
        mock_resp.signature_hash_algorithm = hashes.SHA256()

        with pytest.raises(CertificateError, match="signature verification failed"):
            _verify_ocsp_response_signature(mock_resp, ca_cert)

    def test_delegated_responder_no_eku(self, ca_key, ca_cert):
        """Delegated responder without EKU extension raises CertificateError."""
        # Build a cert without EKU
        responder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        responder_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")]))
            .issuer_name(ca_cert.subject)
            .public_key(responder_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
            .sign(ca_key, hashes.SHA256())
        )

        mock_resp = MagicMock()
        mock_resp.certificates = [responder_cert]

        with pytest.raises(CertificateError, match="no EKU extension"):
            _verify_ocsp_response_signature(mock_resp, ca_cert)

    def test_delegated_responder_wrong_eku(self, ca_key, ca_cert):
        """Delegated responder with wrong EKU raises CertificateError."""
        from cryptography.x509.oid import ExtendedKeyUsageOID

        responder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        responder_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")]))
            .issuer_name(ca_cert.subject)
            .public_key(responder_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        mock_resp = MagicMock()
        mock_resp.certificates = [responder_cert]

        with pytest.raises(CertificateError, match="lacks id-kp-OCSPSigning"):
            _verify_ocsp_response_signature(mock_resp, ca_cert)

    def test_delegated_responder_wrong_issuer(self, ca_key, ca_cert, wrong_ca_key, wrong_ca_cert):
        """Delegated responder issued by wrong CA raises CertificateError."""
        from cryptography.x509.oid import ExtendedKeyUsageOID

        responder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Issued by wrong_ca, not ca_cert
        responder_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")]))
            .issuer_name(wrong_ca_cert.subject)
            .public_key(responder_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                critical=False,
            )
            .sign(wrong_ca_key, hashes.SHA256())
        )

        mock_resp = MagicMock()
        mock_resp.certificates = [responder_cert]

        with pytest.raises(CertificateError, match="not issued by the expected CA"):
            _verify_ocsp_response_signature(mock_resp, ca_cert)

    def test_delegated_responder_valid(self, ca_key, ca_cert):
        """Valid delegated responder with OCSPSigning EKU passes."""
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.x509.oid import ExtendedKeyUsageOID

        responder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        responder_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")]))
            .issuer_name(ca_cert.subject)
            .public_key(responder_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        data = b"ocsp tbs response data"
        sig = responder_key.sign(data, padding.PKCS1v15(), hashes.SHA256())

        mock_resp = MagicMock()
        mock_resp.certificates = [responder_cert]
        mock_resp.signature = sig
        mock_resp.tbs_response_bytes = data
        mock_resp.signature_hash_algorithm = hashes.SHA256()

        # Should not raise
        _verify_ocsp_response_signature(mock_resp, ca_cert)

    def test_delegated_responder_bad_response_sig(self, ca_key, ca_cert):
        """Valid responder cert but bad response signature raises."""
        from cryptography.x509.oid import ExtendedKeyUsageOID

        responder_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        responder_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "OCSP Responder")]))
            .issuer_name(ca_cert.subject)
            .public_key(responder_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
            .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        mock_resp = MagicMock()
        mock_resp.certificates = [responder_cert]
        mock_resp.signature = b"bad-signature"
        mock_resp.tbs_response_bytes = b"data"
        mock_resp.signature_hash_algorithm = hashes.SHA256()

        with pytest.raises(CertificateError, match="signature verification failed"):
            _verify_ocsp_response_signature(mock_resp, ca_cert)


class TestQueryOcspSignatureVerification:
    def test_signature_verification_failure(self, ca_key, ca_cert):
        """OCSP query returns UNAVAILABLE when signature verification fails."""
        from cryptography.x509 import ocsp

        cert = _make_cert_with_aia(ca_key, ca_cert, "http://ocsp.example.com")

        mock_ocsp_resp = MagicMock()
        mock_ocsp_resp.response_status = ocsp.OCSPResponseStatus.SUCCESSFUL
        mock_ocsp_resp.certificate_status = ocsp.OCSPCertStatus.GOOD

        mock_http_resp = MagicMock()
        mock_http_resp.content = b"fake-ocsp-response"
        mock_http_resp.raise_for_status = MagicMock()

        with (
            patch("pki.core.revocation.httpx.post", return_value=mock_http_resp),
            patch("pki.core.revocation.ocsp.load_der_ocsp_response", return_value=mock_ocsp_resp),
            patch(
                "pki.core.revocation._verify_ocsp_response_signature",
                side_effect=CertificateError("bad sig"),
            ),
        ):
            result, detail = _query_ocsp(cert, ca_cert, "http://ocsp.example.com", timeout=10)
            assert result == RevocationResult.UNAVAILABLE
            assert "signature invalid" in detail.lower()
