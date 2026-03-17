"""Tests for pki.core.crl module."""

import pytest

from pki.core.certificate import CertificateError
from pki.core.crl import (
    CRLConfig,
    get_crl_distribution_points,
    get_crl_max_age,
    load_ca_certs_from_pem,
    parse_crl_bytes,
    verify_crl,
)


class TestGetCrlDistributionPoints:
    def test_cert_with_cdp(self, cac_cert):
        urls = get_crl_distribution_points(cac_cert)
        assert urls == ["http://crl.test.example/test.crl"]

    def test_cert_without_cdp(self, ca_cert):
        urls = get_crl_distribution_points(ca_cert)
        assert urls == []


class TestParseCrlBytes:
    def test_parse_der(self, test_crl_der):
        crl = parse_crl_bytes(test_crl_der)
        assert crl is not None

    def test_parse_pem(self, test_crl_pem):
        crl = parse_crl_bytes(test_crl_pem)
        assert crl is not None

    def test_parse_garbage_raises(self):
        with pytest.raises(CertificateError):
            parse_crl_bytes(b"not a crl")


class TestCrlRevocation:
    def test_revoked_serial_in_crl(self, test_crl, revoked_serial):
        entry = test_crl.get_revoked_certificate_by_serial_number(revoked_serial)
        assert entry is not None

    def test_non_revoked_serial(self, test_crl):
        entry = test_crl.get_revoked_certificate_by_serial_number(999999)
        assert entry is None


class TestGetCrlMaxAge:
    def test_no_cdp(self, ca_cert):
        config = CRLConfig(cache_dir="/tmp/test-crls")
        result = get_crl_max_age(ca_cert, config)
        assert result is None

    def test_no_cache_returns_inf(self, cac_cert, tmp_path):
        config = CRLConfig(cache_dir=str(tmp_path / "empty"))
        result = get_crl_max_age(cac_cert, config)
        assert result == float("inf")

    def test_cached_crl_returns_age(self, cac_cert, tmp_path, test_crl_der):
        import hashlib

        config = CRLConfig(cache_dir=str(tmp_path))
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        age = get_crl_max_age(cac_cert, config)
        assert age is not None
        assert age >= 0
        assert age < 5  # just written


class TestVerifyCrl:
    def test_valid_signature(self, test_crl, ca_cert):
        assert verify_crl(test_crl, [ca_cert], strict=True) is True

    def test_invalid_signature_strict(self, test_crl, wrong_ca_cert):
        """CRL signed by ca_key but verified against wrong_ca_cert should fail."""
        with pytest.raises(CertificateError, match="No CA certificate found"):
            verify_crl(test_crl, [wrong_ca_cert], strict=True)

    def test_invalid_signature_non_strict(self, test_crl, wrong_ca_cert):
        assert verify_crl(test_crl, [wrong_ca_cert], strict=False) is False

    def test_no_matching_issuer_strict(self, test_crl):
        with pytest.raises(CertificateError, match="No CA certificate found"):
            verify_crl(test_crl, [], strict=True)

    def test_no_matching_issuer_non_strict(self, test_crl):
        assert verify_crl(test_crl, [], strict=False) is False

    def test_expired_next_update_strict(self, expired_crl, ca_cert):
        with pytest.raises(CertificateError, match="CRL has expired"):
            verify_crl(expired_crl, [ca_cert], strict=True)

    def test_expired_next_update_non_strict(self, expired_crl, ca_cert):
        assert verify_crl(expired_crl, [ca_cert], strict=False) is False


class TestLoadCaCertsFromPem:
    def test_load_single_cert(self, ca_cert_pem):
        certs = load_ca_certs_from_pem(ca_cert_pem)
        assert len(certs) == 1

    def test_load_str(self, ca_cert_pem):
        certs = load_ca_certs_from_pem(ca_cert_pem.decode())
        assert len(certs) == 1

    def test_load_multiple(self, ca_cert_pem, wrong_ca_cert):
        from cryptography.hazmat.primitives.serialization import Encoding

        bundle = ca_cert_pem + wrong_ca_cert.public_bytes(Encoding.PEM)
        certs = load_ca_certs_from_pem(bundle)
        assert len(certs) == 2
