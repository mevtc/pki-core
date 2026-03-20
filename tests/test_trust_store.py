"""Tests for trust_store module."""

from unittest.mock import patch

import pytest

from pki.core.providers import AuthProvider, TrustStoreSource
from pki.core.trust_store import build_bundle_for_provider, merge_and_deduplicate


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
