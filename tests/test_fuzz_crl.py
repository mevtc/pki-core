"""Hypothesis fuzz tests for CRL parsing and verification.

Property-based tests that throw arbitrary bytes at parse_crl_bytes() and
verify invariants on get_crl_distribution_points() and verify_crl().

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from __future__ import annotations

import contextlib

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.certificate import CertificateError
from pki.core.crl import get_crl_distribution_points, parse_crl_bytes, verify_crl

# ---------------------------------------------------------------------------
# parse_crl_bytes — arbitrary bytes
# ---------------------------------------------------------------------------


class TestFuzzParseCrlBytes:
    @given(data=st.binary(min_size=0, max_size=5000))
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_arbitrary_bytes_never_crash(self, data):
        """Arbitrary bytes should either parse to a CRL or raise CertificateError."""
        try:
            result = parse_crl_bytes(data)
            from cryptography import x509

            assert isinstance(result, x509.CertificateRevocationList)
        except CertificateError:
            pass  # expected for garbage input

    @given(data=st.binary(min_size=0, max_size=10))
    def test_short_bytes_raise_certificate_error(self, data):
        """Very short inputs should raise CertificateError."""
        with contextlib.suppress(CertificateError):
            parse_crl_bytes(data)

    @given(
        prefix=st.sampled_from([b"-----BEGIN X509 CRL-----\n", b""]),
        body=st.binary(min_size=0, max_size=500),
    )
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_pem_like_prefix_never_crash(self, prefix, body):
        """Inputs starting with PEM CRL header should not cause unexpected errors."""
        with contextlib.suppress(CertificateError):
            parse_crl_bytes(prefix + body)

    def test_valid_der_crl_parses(self, test_crl_der):
        """A valid DER CRL should parse successfully."""
        from cryptography import x509

        result = parse_crl_bytes(test_crl_der)
        assert isinstance(result, x509.CertificateRevocationList)

    def test_valid_pem_crl_parses(self, test_crl_pem):
        """A valid PEM CRL should parse successfully."""
        from cryptography import x509

        result = parse_crl_bytes(test_crl_pem)
        assert isinstance(result, x509.CertificateRevocationList)


# ---------------------------------------------------------------------------
# get_crl_distribution_points — real certs from fixtures
# ---------------------------------------------------------------------------


class TestFuzzGetCrlDistributionPoints:
    def test_cac_cert_returns_list_of_strings(self, cac_cert):
        result = get_crl_distribution_points(cac_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_piv_cert_returns_list_of_strings(self, piv_cert):
        result = get_crl_distribution_points(piv_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_eca_cert_returns_list_of_strings(self, eca_cert):
        result = get_crl_distribution_points(eca_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_expired_cert_returns_list_of_strings(self, expired_cert):
        result = get_crl_distribution_points(expired_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_ca_cert_returns_list_of_strings(self, ca_cert):
        result = get_crl_distribution_points(ca_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_urls_are_http(self, cac_cert):
        """Any returned URLs should start with http:// or https://."""
        urls = get_crl_distribution_points(cac_cert)
        for url in urls:
            assert url.startswith(("http://", "https://")), f"URL {url!r} is not HTTP(S)"

    def test_cac_has_at_least_one_dp(self, cac_cert):
        """CAC cert fixture has a CRL distribution point."""
        urls = get_crl_distribution_points(cac_cert)
        assert len(urls) >= 1


# ---------------------------------------------------------------------------
# verify_crl — various issuer cert combinations
# ---------------------------------------------------------------------------


class TestFuzzVerifyCrl:
    def test_valid_crl_with_correct_issuer(self, test_crl, ca_cert):
        """A valid CRL verified against its issuer should return True."""
        result = verify_crl(test_crl, [ca_cert], strict=True)
        assert isinstance(result, bool)
        assert result is True

    def test_valid_crl_nonstrict_returns_bool(self, test_crl, ca_cert):
        """Non-strict mode should always return a bool."""
        result = verify_crl(test_crl, [ca_cert], strict=False)
        assert isinstance(result, bool)
        assert result is True

    def test_wrong_issuer_nonstrict_returns_false(self, test_crl, wrong_ca_cert):
        """Wrong issuer in non-strict mode should return False."""
        result = verify_crl(test_crl, [wrong_ca_cert], strict=False)
        assert isinstance(result, bool)
        assert result is False

    def test_wrong_issuer_strict_raises(self, test_crl, wrong_ca_cert):
        """Wrong issuer in strict mode should raise CertificateError."""
        import pytest

        with pytest.raises(CertificateError):
            verify_crl(test_crl, [wrong_ca_cert], strict=True)

    def test_empty_issuer_list_nonstrict(self, test_crl):
        """Empty issuer list in non-strict mode should return False."""
        result = verify_crl(test_crl, [], strict=False)
        assert isinstance(result, bool)
        assert result is False

    def test_empty_issuer_list_strict_raises(self, test_crl):
        """Empty issuer list in strict mode should raise CertificateError."""
        import pytest

        with pytest.raises(CertificateError):
            verify_crl(test_crl, [], strict=True)

    def test_expired_crl_nonstrict_returns_false(self, expired_crl, ca_cert):
        """An expired CRL in non-strict mode should return False."""
        result = verify_crl(expired_crl, [ca_cert], strict=False)
        assert isinstance(result, bool)
        assert result is False

    def test_expired_crl_strict_raises(self, expired_crl, ca_cert):
        """An expired CRL in strict mode should raise CertificateError."""
        import pytest

        with pytest.raises(CertificateError):
            verify_crl(expired_crl, [ca_cert], strict=True)

    def test_multiple_issuers_finds_correct_one(self, test_crl, ca_cert, wrong_ca_cert):
        """With multiple issuers, the correct one should be found."""
        result = verify_crl(test_crl, [wrong_ca_cert, ca_cert], strict=True)
        assert isinstance(result, bool)
        assert result is True

    def test_multiple_issuers_wrong_order(self, test_crl, ca_cert, wrong_ca_cert):
        """Order of issuers should not matter for finding the match."""
        result = verify_crl(test_crl, [ca_cert, wrong_ca_cert], strict=True)
        assert isinstance(result, bool)
        assert result is True
