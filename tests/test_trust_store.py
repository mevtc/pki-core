"""Tests for trust_store module."""

import io
import zipfile
from unittest.mock import MagicMock, patch

import httpx
import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    serialize_certificates,
)

from pki.core.providers import AuthProvider, ProviderRegistry, TrustStoreSource
from pki.core.trust_store import (
    build_bundle_for_provider,
    build_ca_bundle_for_providers,
    download,
    fetch_trust_store_source,
    merge_and_deduplicate,
)


@pytest.fixture
def mock_provider(ca_cert):
    """Provider with a mock trust store source."""
    return AuthProvider(
        name="Test",
        display_name="Test Provider",
        auth_oids=frozenset(),
        cn_parser=lambda id: None,
        primary_id_selector=lambda id: f"dn:{id.subject_dn}",
        trust_store_sources=(
            TrustStoreSource(
                url="https://example.com/bundle.p7c", format="pkcs7_der", label="test"
            ),
        ),
    )


@pytest.fixture
def empty_provider():
    """Provider with no trust store sources."""
    return AuthProvider(
        name="Empty",
        display_name="Empty Provider",
        auth_oids=frozenset(),
        cn_parser=lambda id: None,
        primary_id_selector=lambda id: "",
        trust_store_sources=(),
    )


class TestMergeAndDeduplicate:
    def test_deduplicates_identical_certs(self, ca_cert):
        cert_lists = [
            ("source-a", [ca_cert]),
            ("source-b", [ca_cert]),
        ]
        _pem, stats = merge_and_deduplicate(cert_lists)
        assert stats["total"] == 1

    def test_empty_input(self):
        pem, stats = merge_and_deduplicate([])
        assert pem == ""
        assert stats["total"] == 0

    def test_filter_fn(self, ca_cert):
        cert_lists = [("source", [ca_cert])]
        _pem, stats = merge_and_deduplicate(cert_lists, filter_fn=lambda c: False)
        assert stats["total"] == 0


class TestBuildBundleForProvider:
    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_builds_bundle(self, mock_fetch, mock_provider, ca_cert):
        mock_fetch.return_value = [ca_cert]
        pem, stats = build_bundle_for_provider(mock_provider)
        assert "BEGIN CERTIFICATE" in pem
        assert stats["total"] == 1
        mock_fetch.assert_called_once()

    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_writes_to_file(self, mock_fetch, mock_provider, ca_cert, tmp_path):
        mock_fetch.return_value = [ca_cert]
        output = str(tmp_path / "bundle.pem")
        pem, _stats = build_bundle_for_provider(mock_provider, output_path=output)
        assert (tmp_path / "bundle.pem").read_text() == pem

    def test_no_sources_raises(self, empty_provider):
        with pytest.raises(RuntimeError, match="No certificates fetched"):
            build_bundle_for_provider(empty_provider)

    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_fetch_failure_raises(self, mock_fetch, mock_provider):
        mock_fetch.side_effect = Exception("network error")
        with pytest.raises(RuntimeError, match="No certificates fetched"):
            build_bundle_for_provider(mock_provider)

    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_with_filter_fn(self, mock_fetch, mock_provider, ca_cert):
        """filter_fn is passed through to merge_and_deduplicate."""
        mock_fetch.return_value = [ca_cert]
        _pem, stats = build_bundle_for_provider(mock_provider, filter_fn=lambda c: False)
        assert stats["total"] == 0


# ---------------------------------------------------------------------------
# download()
# ---------------------------------------------------------------------------


class TestDownload:
    def test_successful_download(self):
        """Successful download returns response bytes."""
        mock_resp = MagicMock()
        mock_resp.content = b"test data"
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.trust_store.httpx.get", return_value=mock_resp):
            data = download("https://example.com/bundle.p7c")
            assert data == b"test data"

    def test_exceeds_max_bytes(self):
        """Download exceeding max_bytes raises ValueError."""
        mock_resp = MagicMock()
        mock_resp.content = b"x" * 100
        mock_resp.raise_for_status = MagicMock()
        with (
            patch("pki.core.trust_store.httpx.get", return_value=mock_resp),
            pytest.raises(ValueError, match="exceeds size limit"),
        ):
            download("https://example.com/big.p7c", max_bytes=10)

    def test_network_error_propagates(self):
        """Network error propagates from httpx."""
        with (
            patch("pki.core.trust_store.httpx.get", side_effect=httpx.ConnectError("refused")),
            pytest.raises(httpx.ConnectError),
        ):
            download("https://example.com/bundle.p7c")


# ---------------------------------------------------------------------------
# fetch_trust_store_source()
# ---------------------------------------------------------------------------


class TestFetchTrustStoreSource:
    def test_pkcs7_der_format(self, ca_cert):
        """pkcs7_der format fetches and parses DER PKCS7."""
        p7_data = serialize_certificates([ca_cert], Encoding.DER)
        source = TrustStoreSource(url="https://example.com/bundle.p7c", format="pkcs7_der")

        mock_resp = MagicMock()
        mock_resp.content = p7_data
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.trust_store.httpx.get", return_value=mock_resp):
            certs = fetch_trust_store_source(source)
            assert len(certs) == 1

    def test_der_format(self, ca_cert):
        """der format fetches and parses a single DER certificate."""
        der_data = ca_cert.public_bytes(Encoding.DER)
        source = TrustStoreSource(url="https://example.com/cert.der", format="der")

        mock_resp = MagicMock()
        mock_resp.content = der_data
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.trust_store.httpx.get", return_value=mock_resp):
            certs = fetch_trust_store_source(source)
            assert len(certs) == 1

    def test_pkcs7_zip_format(self, ca_cert):
        """pkcs7_zip format fetches ZIP, parses PKCS7 entries."""
        p7_data = serialize_certificates([ca_cert], Encoding.DER)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("certs/bundle.p7b", p7_data)
        zip_bytes = buf.getvalue()

        source = TrustStoreSource(url="https://example.com/bundle.zip", format="pkcs7_zip")
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.trust_store.httpx.get", return_value=mock_resp):
            certs = fetch_trust_store_source(source)
            assert len(certs) >= 1

    def test_pkcs7_zip_skips_suspicious_entries(self, ca_cert):
        """ZIP entries with path traversal or absolute paths are skipped."""
        p7_data = serialize_certificates([ca_cert], Encoding.DER)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../evil.p7b", p7_data)
            zf.writestr("/absolute.p7b", p7_data)
            zf.writestr("readme.txt", b"not a p7b")
        zip_bytes = buf.getvalue()

        source = TrustStoreSource(url="https://example.com/bundle.zip", format="pkcs7_zip")
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.trust_store.httpx.get", return_value=mock_resp):
            certs = fetch_trust_store_source(source)
            assert certs == []

    def test_pkcs7_zip_unparseable_entry(self):
        """ZIP with unparseable PKCS7 entry logs warning and returns empty."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("bad.p7b", b"not a pkcs7 bundle")
        zip_bytes = buf.getvalue()

        source = TrustStoreSource(url="https://example.com/bundle.zip", format="pkcs7_zip")
        mock_resp = MagicMock()
        mock_resp.content = zip_bytes
        mock_resp.raise_for_status = MagicMock()
        with patch("pki.core.trust_store.httpx.get", return_value=mock_resp):
            certs = fetch_trust_store_source(source)
            assert certs == []

    def test_unknown_format_returns_empty(self):
        """Unknown format returns empty list."""
        source = TrustStoreSource(url="https://example.com/bundle", format="unknown_format")
        certs = fetch_trust_store_source(source)
        assert certs == []


# ---------------------------------------------------------------------------
# build_ca_bundle_for_providers()
# ---------------------------------------------------------------------------


class TestBuildCaBundleForProviders:
    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_builds_bundle_from_registry(self, mock_fetch, ca_cert):
        """Builds a PEM bundle from all providers in a registry."""
        mock_fetch.return_value = [ca_cert]
        provider = AuthProvider(
            name="TestProv",
            display_name="Test Provider",
            auth_oids=frozenset(),
            cn_parser=lambda id: None,
            primary_id_selector=lambda id: "",
            trust_store_sources=(
                TrustStoreSource(
                    url="https://example.com/bundle.p7c",
                    format="pkcs7_der",
                    label="test",
                ),
            ),
        )
        registry = ProviderRegistry()
        registry.register(provider)

        pem, stats = build_ca_bundle_for_providers(registry)
        assert "BEGIN CERTIFICATE" in pem
        assert stats["total"] == 1

    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_writes_to_file(self, mock_fetch, ca_cert, tmp_path):
        """Writes PEM bundle to output_path."""
        mock_fetch.return_value = [ca_cert]
        provider = AuthProvider(
            name="TestProv",
            display_name="Test Provider",
            auth_oids=frozenset(),
            cn_parser=lambda id: None,
            primary_id_selector=lambda id: "",
            trust_store_sources=(
                TrustStoreSource(url="https://example.com/b.p7c", format="pkcs7_der"),
            ),
        )
        registry = ProviderRegistry()
        registry.register(provider)

        output = str(tmp_path / "ca-bundle.pem")
        pem, _stats = build_ca_bundle_for_providers(registry, output_path=output)
        assert (tmp_path / "ca-bundle.pem").read_text() == pem

    @patch("pki.core.trust_store.fetch_trust_store_source")
    def test_all_fetches_fail_raises(self, mock_fetch):
        """When all fetches fail, raises RuntimeError."""
        mock_fetch.side_effect = Exception("network error")
        provider = AuthProvider(
            name="FailProv",
            display_name="Fail Provider",
            auth_oids=frozenset(),
            cn_parser=lambda id: None,
            primary_id_selector=lambda id: "",
            trust_store_sources=(
                TrustStoreSource(url="https://example.com/b.p7c", format="pkcs7_der"),
            ),
        )
        registry = ProviderRegistry()
        registry.register(provider)

        with pytest.raises(RuntimeError, match="No certificates fetched"):
            build_ca_bundle_for_providers(registry)

    def test_no_sources_raises(self):
        """Registry with provider having no sources raises RuntimeError."""
        provider = AuthProvider(
            name="EmptyProv",
            display_name="Empty Provider",
            auth_oids=frozenset(),
            cn_parser=lambda id: None,
            primary_id_selector=lambda id: "",
            trust_store_sources=(),
        )
        registry = ProviderRegistry()
        registry.register(provider)

        with pytest.raises(RuntimeError, match="No certificates fetched"):
            build_ca_bundle_for_providers(registry)
