"""Tests for pki.core.crl module."""

import hashlib
import os
import time
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import Encoding

from pki.core.certificate import CertificateError
from pki.core.crl import (
    CRLConfig,
    CRLRefreshError,
    _refresh_crl_background,
    check_revocation,
    get_crl,
    get_crl_distribution_points,
    get_crl_max_age,
    load_ca_certs_from_pem,
    parse_crl_bytes,
    prefetch_crls,
    refresh_crl,
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


class TestCheckRevocation:
    """Tests for check_revocation() — the main CRL-based revocation check."""

    def test_no_cdp_skips_check(self, ca_cert):
        """Cert with no CRL distribution points skips check silently."""
        config = CRLConfig(cache_dir="/tmp/test-crls")
        # Should not raise
        check_revocation(ca_cert, config)

    def test_revoked_cert_raises(self, cac_cert, ca_cert, test_crl, tmp_path):
        """Certificate whose serial is in the CRL raises CertificateError."""
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl.public_bytes(Encoding.DER))

        config = CRLConfig(cache_dir=str(tmp_path), strict=True)
        with pytest.raises(CertificateError, match="revoked"):
            check_revocation(cac_cert, config)

    def test_non_revoked_cert_passes(self, cac_cert, ca_cert, tmp_path, ca_key):
        """Certificate not in the CRL passes without error."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        # Build a CRL that does NOT contain cac_cert's serial
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(ca_cert.subject)
        builder = builder.last_update(datetime.datetime(2024, 6, 1, tzinfo=datetime.UTC))
        builder = builder.next_update(datetime.datetime(2030, 6, 1, tzinfo=datetime.UTC))
        empty_crl = builder.sign(ca_key, hashes.SHA256())

        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(empty_crl.public_bytes(Encoding.DER))

        config = CRLConfig(cache_dir=str(tmp_path), strict=True)
        # Should not raise
        check_revocation(cac_cert, config)

    def test_with_issuer_certs_verifies_crl(self, cac_cert, ca_cert, test_crl, tmp_path):
        """When issuer_certs is provided, CRL signature is verified."""
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl.public_bytes(Encoding.DER))

        config = CRLConfig(cache_dir=str(tmp_path), strict=True)
        # Should raise for revoked cert, but also exercise the verify path
        with pytest.raises(CertificateError, match="revoked"):
            check_revocation(cac_cert, config, issuer_certs=[ca_cert])

    def test_without_issuer_certs_skips_verification(self, cac_cert, ca_cert, test_crl, tmp_path):
        """Without issuer_certs, CRL signature verification is skipped."""
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl.public_bytes(Encoding.DER))

        config = CRLConfig(cache_dir=str(tmp_path), strict=True)
        with pytest.raises(CertificateError, match="revoked"):
            check_revocation(cac_cert, config, issuer_certs=None)

    def test_fetch_failure_strict_raises(self, cac_cert, tmp_path):
        """When CRL fetch fails in strict mode, raises CertificateError."""
        config = CRLConfig(cache_dir=str(tmp_path), strict=True, fetch_timeout=1)
        with (
            patch("pki.core.crl.httpx.get", side_effect=httpx.ConnectError("refused")),
            pytest.raises(CertificateError, match="CRL unavailable"),
        ):
            check_revocation(cac_cert, config)

    def test_fetch_failure_non_strict_continues(self, cac_cert, tmp_path):
        """When CRL fetch fails in non-strict mode, allows through."""
        config = CRLConfig(cache_dir=str(tmp_path), strict=False, fetch_timeout=1)
        with patch("pki.core.crl.httpx.get", side_effect=httpx.ConnectError("refused")):
            # Should not raise
            check_revocation(cac_cert, config)


class TestGetCrl:
    """Tests for get_crl() — stale-while-revalidate cache strategy."""

    def test_fresh_cache_returns_immediately(self, test_crl_der, tmp_path):
        """Fresh cached CRL is returned without network I/O."""
        url = "http://example.com/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        crl = get_crl(url, config)
        assert crl is not None

    def test_stale_cache_returns_and_spawns_background(self, test_crl_der, tmp_path):
        """Stale cached CRL is returned immediately; background refresh is spawned."""
        url = "http://example.com/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)
        # Make cache stale by setting mtime in the past
        old_time = time.time() - 7200
        os.utime(cache_file, (old_time, old_time))

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        with patch("pki.core.crl.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            crl = get_crl(url, config)
            assert crl is not None
            mock_thread.assert_called_once()
            mock_thread.return_value.start.assert_called_once()

    def test_max_acceptable_age_forces_refresh(self, test_crl_der, tmp_path):
        """When cache exceeds max_acceptable_age, forces a synchronous refresh."""
        url = "http://example.com/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)
        # Make cache very old
        old_time = time.time() - 100000
        os.utime(cache_file, (old_time, old_time))

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600, max_acceptable_age=86400)
        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            crl = get_crl(url, config)
            assert crl is not None

    def test_no_cache_fetches_synchronously(self, test_crl_der, tmp_path):
        """When no cache exists, fetches synchronously."""
        url = "http://example.com/test.crl"
        config = CRLConfig(cache_dir=str(tmp_path / "nocache"))

        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            crl = get_crl(url, config)
            assert crl is not None

    def test_fresh_cache_verified_with_issuer_certs(self, test_crl_der, ca_cert, tmp_path):
        """Fresh cached CRL is signature-verified when issuer_certs is provided."""
        url = "http://example.com/verified.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        crl = get_crl(url, config, issuer_certs=[ca_cert])
        assert crl is not None

    def test_fresh_cache_rejects_wrong_issuer(self, test_crl_der, wrong_ca_cert, tmp_path):
        """Cached CRL signed by unknown CA is rejected when issuer_certs is provided."""
        url = "http://example.com/poisoned.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600, strict=True)
        with pytest.raises(CertificateError, match="No CA certificate found"):
            get_crl(url, config, issuer_certs=[wrong_ca_cert])

    def test_stale_cache_verified_with_issuer_certs(self, test_crl_der, ca_cert, tmp_path):
        """Stale cached CRL is also signature-verified when issuer_certs is provided."""
        url = "http://example.com/stale-verified.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)
        old_time = time.time() - 7200
        os.utime(cache_file, (old_time, old_time))

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        with patch("pki.core.crl.threading.Thread") as mock_thread:
            mock_thread.return_value = MagicMock()
            crl = get_crl(url, config, issuer_certs=[ca_cert])
            assert crl is not None

    def test_without_issuer_certs_skips_verification(self, test_crl_der, tmp_path):
        """Without issuer_certs, cached CRL is returned without signature check."""
        url = "http://example.com/no-verify.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        # Should succeed even though no issuer_certs — backward compatible
        crl = get_crl(url, config)
        assert crl is not None


class TestRefreshCrl:
    """Tests for refresh_crl() — fetch, cache, and return a CRL."""

    def test_successful_refresh(self, test_crl_der, tmp_path):
        """Successful refresh fetches, caches, and returns a CRL."""
        url = "http://example.com/test.crl"
        cache_file = tmp_path / "test.crl"
        config = CRLConfig(cache_dir=str(tmp_path))

        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            crl = refresh_crl(url, cache_file, config)
            assert crl is not None
            assert cache_file.exists()

    def test_oversized_crl_raises(self, test_crl_der, tmp_path):
        """CRL exceeding max_crl_bytes raises ValueError."""
        url = "http://example.com/test.crl"
        cache_file = tmp_path / "test.crl"
        config = CRLConfig(cache_dir=str(tmp_path), max_crl_bytes=10)

        mock_resp = MagicMock()
        mock_resp.content = test_crl_der  # much larger than 10 bytes
        mock_resp.raise_for_status = MagicMock()
        with (
            patch("pki.core.crl.httpx.get", return_value=mock_resp),
            pytest.raises(ValueError, match="exceeds size limit"),
        ):
            refresh_crl(url, cache_file, config)

    def test_network_failure_raises(self, tmp_path):
        """Network failure during refresh propagates the exception."""
        url = "http://example.com/test.crl"
        cache_file = tmp_path / "test.crl"
        config = CRLConfig(cache_dir=str(tmp_path))

        with (
            patch("pki.core.crl.httpx.get", side_effect=httpx.ConnectError("refused")),
            pytest.raises(httpx.ConnectError),
        ):
            refresh_crl(url, cache_file, config)

    def test_default_config_when_none(self, test_crl_der, tmp_path):
        """When config is None, uses default CRLConfig."""
        url = "http://example.com/test.crl"
        cache_file = tmp_path / "test.crl"

        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            crl = refresh_crl(url, cache_file, config=None)
            assert crl is not None


class TestRefreshCrlBackground:
    """Tests for _refresh_crl_background()."""

    def test_success(self, test_crl_der, tmp_path):
        """Background refresh succeeds without raising."""
        url = "http://example.com/test.crl"
        cache_file = tmp_path / "bg_test.crl"
        config = CRLConfig(cache_dir=str(tmp_path))

        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            _refresh_crl_background(url, cache_file, config)
            assert cache_file.exists()

    def test_failure_raises_crl_refresh_error(self, tmp_path):
        """Background refresh failure raises CRLRefreshError."""
        url = "http://example.com/test.crl"
        cache_file = tmp_path / "bg_fail.crl"
        config = CRLConfig(cache_dir=str(tmp_path))

        with (
            patch("pki.core.crl.httpx.get", side_effect=httpx.ConnectError("refused")),
            pytest.raises(CRLRefreshError, match="Background CRL refresh failed"),
        ):
            _refresh_crl_background(url, cache_file, config)


class TestPrefetchCrls:
    """Tests for prefetch_crls() — proactive CRL caching."""

    def test_no_cdp_returns_empty(self, ca_cert):
        """Cert with no CDP returns empty dict."""
        config = CRLConfig(cache_dir="/tmp/test-crls")
        result = prefetch_crls(ca_cert, config)
        assert result == {}

    def test_fresh_cache_skipped(self, cac_cert, test_crl_der, tmp_path):
        """Fresh cached CRL is skipped."""
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        result = prefetch_crls(cac_cert, config)
        assert result[url] == "skipped (fresh)"

    def test_stale_cache_refreshed(self, cac_cert, test_crl_der, tmp_path):
        """Stale cached CRL is refreshed."""
        url = "http://crl.test.example/test.crl"
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = tmp_path / f"{url_hash}.crl"
        cache_file.write_bytes(test_crl_der)
        # Make stale
        old_time = time.time() - 7200
        os.utime(cache_file, (old_time, old_time))

        config = CRLConfig(cache_dir=str(tmp_path), cache_ttl=3600)
        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            result = prefetch_crls(cac_cert, config)
            assert result[url] == "refreshed"

    def test_no_cache_refreshed(self, cac_cert, test_crl_der, tmp_path):
        """No cached CRL triggers a fetch."""
        config = CRLConfig(cache_dir=str(tmp_path))
        mock_resp = MagicMock()
        mock_resp.content = test_crl_der
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.crl.httpx.get", return_value=mock_resp):
            result = prefetch_crls(cac_cert, config)
            url = "http://crl.test.example/test.crl"
            assert result[url] == "refreshed"

    def test_fetch_error_recorded(self, cac_cert, tmp_path):
        """Fetch error is recorded in results dict."""
        config = CRLConfig(cache_dir=str(tmp_path), fetch_timeout=1)
        with patch("pki.core.crl.httpx.get", side_effect=httpx.ConnectError("refused")):
            result = prefetch_crls(cac_cert, config)
            url = "http://crl.test.example/test.crl"
            assert result[url].startswith("error:")
