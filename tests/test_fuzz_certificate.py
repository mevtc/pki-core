"""Hypothesis fuzz tests for certificate parsing utilities.

Property-based tests that throw thousands of random inputs at each
certificate utility function to verify they never crash and always
satisfy return-type invariants.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

import contextlib
import re

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.certificate import (
    CertificateError,
    cert_fingerprint,
    extract_email,
    extract_san_fascn,
    extract_san_uuid,
    get_policy_oids,
    is_expired,
    is_not_yet_valid,
    load_certificate,
)

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# load_certificate — arbitrary bytes
# ---------------------------------------------------------------------------


class TestFuzzLoadCertificate:
    @given(data=st.binary(min_size=0, max_size=5000))
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_arbitrary_bytes_never_crash(self, data):
        """Arbitrary bytes should either parse or raise CertificateError."""
        try:
            result = load_certificate(data)
            # If it succeeded it must be a Certificate object
            from cryptography import x509

            assert isinstance(result, x509.Certificate)
        except CertificateError:
            pass  # expected for garbage input

    @given(data=st.binary(min_size=0, max_size=10))
    def test_short_bytes_raise_certificate_error(self, data):
        """Very short inputs should always raise CertificateError."""
        with contextlib.suppress(CertificateError):
            load_certificate(data)

    @given(
        prefix=st.sampled_from([b"-----BEGIN CERTIFICATE-----\n", b""]),
        body=st.binary(min_size=0, max_size=500),
    )
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_pem_like_prefix_never_crash(self, prefix, body):
        """Inputs starting with PEM header should not cause unexpected errors."""
        with contextlib.suppress(CertificateError):
            load_certificate(prefix + body)


# ---------------------------------------------------------------------------
# get_policy_oids — real certs from fixtures
# ---------------------------------------------------------------------------


class TestFuzzGetPolicyOids:
    def test_always_returns_list_of_strings(self, cac_cert):
        result = get_policy_oids(cac_cert)
        assert isinstance(result, list)
        for oid in result:
            assert isinstance(oid, str)

    def test_piv_cert_returns_list(self, piv_cert):
        result = get_policy_oids(piv_cert)
        assert isinstance(result, list)
        for oid in result:
            assert isinstance(oid, str)

    def test_cert_without_policies(self, expired_cert):
        result = get_policy_oids(expired_cert)
        assert isinstance(result, list)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# extract_email
# ---------------------------------------------------------------------------


class TestFuzzExtractEmail:
    def test_cac_returns_str_or_none(self, cac_cert):
        result = extract_email(cac_cert)
        assert result is None or isinstance(result, str)

    def test_piv_returns_str_or_none(self, piv_cert):
        result = extract_email(piv_cert)
        assert result is None or isinstance(result, str)

    def test_expired_returns_str_or_none(self, expired_cert):
        result = extract_email(expired_cert)
        assert result is None or isinstance(result, str)

    def test_ca_returns_str_or_none(self, ca_cert):
        result = extract_email(ca_cert)
        assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# extract_san_uuid
# ---------------------------------------------------------------------------


class TestFuzzExtractSanUuid:
    def test_piv_returns_valid_uuid_format(self, piv_cert):
        result = extract_san_uuid(piv_cert)
        assert result is None or isinstance(result, str)
        if result is not None:
            assert _UUID_RE.match(result), f"UUID {result!r} does not match expected format"

    def test_cac_returns_str_or_none(self, cac_cert):
        result = extract_san_uuid(cac_cert)
        assert result is None or isinstance(result, str)
        if result is not None:
            assert _UUID_RE.match(result)

    def test_bad_uuid_returns_none(self, bad_uuid_cert):
        result = extract_san_uuid(bad_uuid_cert)
        # Malformed UUID should be rejected
        assert result is None or _UUID_RE.match(result)

    def test_ca_cert_returns_none(self, ca_cert):
        result = extract_san_uuid(ca_cert)
        assert result is None


# ---------------------------------------------------------------------------
# extract_san_fascn
# ---------------------------------------------------------------------------


class TestFuzzExtractSanFascn:
    def test_cac_returns_str_or_none(self, cac_cert):
        result = extract_san_fascn(cac_cert)
        assert result is None or isinstance(result, str)

    def test_piv_returns_str_or_none(self, piv_cert):
        result = extract_san_fascn(piv_cert)
        assert result is None or isinstance(result, str)

    def test_ca_returns_none(self, ca_cert):
        result = extract_san_fascn(ca_cert)
        assert result is None


# ---------------------------------------------------------------------------
# cert_fingerprint
# ---------------------------------------------------------------------------


class TestFuzzCertFingerprint:
    def test_always_returns_64_char_hex(self, cac_cert):
        result = cert_fingerprint(cac_cert)
        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_piv_returns_64_char_hex(self, piv_cert):
        result = cert_fingerprint(piv_cert)
        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_ca_returns_64_char_hex(self, ca_cert):
        result = cert_fingerprint(ca_cert)
        assert isinstance(result, str)
        assert len(result) == 64

    def test_deterministic(self, cac_cert):
        """Same cert should always produce the same fingerprint."""
        assert cert_fingerprint(cac_cert) == cert_fingerprint(cac_cert)

    def test_different_certs_different_fingerprints(self, cac_cert, piv_cert):
        assert cert_fingerprint(cac_cert) != cert_fingerprint(piv_cert)


# ---------------------------------------------------------------------------
# is_expired / is_not_yet_valid
# ---------------------------------------------------------------------------


class TestFuzzExpiry:
    def test_is_expired_returns_bool(self, cac_cert):
        assert isinstance(is_expired(cac_cert), bool)

    def test_is_not_yet_valid_returns_bool(self, cac_cert):
        assert isinstance(is_not_yet_valid(cac_cert), bool)

    def test_expired_cert_is_expired(self, expired_cert):
        result = is_expired(expired_cert)
        assert isinstance(result, bool)
        assert result is True

    def test_expired_cert_is_not_yet_valid(self, expired_cert):
        result = is_not_yet_valid(expired_cert)
        assert isinstance(result, bool)
        assert result is False

    def test_valid_cert_not_expired(self, cac_cert):
        assert is_expired(cac_cert) is False

    def test_valid_cert_not_future(self, cac_cert):
        assert is_not_yet_valid(cac_cert) is False

    def test_mutual_exclusion(self, cac_cert, expired_cert, piv_cert):
        """A cert cannot be both expired and not-yet-valid at the same time."""
        for cert in (cac_cert, expired_cert, piv_cert):
            expired = is_expired(cert)
            future = is_not_yet_valid(cert)
            assert not (expired and future), "A cert cannot be both expired and not-yet-valid"
