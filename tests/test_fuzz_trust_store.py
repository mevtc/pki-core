"""Hypothesis fuzz tests for trust store merge and deduplication.

Property-based tests that verify merge_and_deduplicate() maintains
its deduplication invariant regardless of input ordering and duplication.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.certificate import cert_fingerprint
from pki.core.trust_store import merge_and_deduplicate

# ---------------------------------------------------------------------------
# merge_and_deduplicate — random orderings and duplicates
# ---------------------------------------------------------------------------


class TestFuzzMergeAndDeduplicate:
    @given(data=st.data())
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_deduplication_invariant(
        self, data, cac_cert, piv_cert, eca_cert, ca_cert, expired_cert
    ):
        """Output should have fewer or equal certs than total input, all unique by fingerprint."""
        all_certs = [cac_cert, piv_cert, eca_cert, ca_cert, expired_cert]

        # Build random cert lists with random duplicates
        num_sources = data.draw(st.integers(min_value=1, max_value=4))
        cert_lists = []
        total_input = 0
        for i in range(num_sources):
            source_certs = data.draw(
                st.lists(
                    st.sampled_from(all_certs),
                    min_size=0,
                    max_size=10,
                )
            )
            cert_lists.append((f"source_{i}", source_certs))
            total_input += len(source_certs)

        pem_bundle, stats = merge_and_deduplicate(cert_lists)

        # Return type checks
        assert isinstance(pem_bundle, str)
        assert isinstance(stats, dict)
        assert "total" in stats
        assert isinstance(stats["total"], int)

        # Deduplication invariant: output <= input
        assert stats["total"] <= total_input

        # Uniqueness invariant: total should be <= number of distinct certs
        assert stats["total"] <= len(all_certs)

    @given(data=st.data())
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_output_fingerprints_are_unique(self, data, cac_cert, piv_cert, eca_cert, ca_cert):
        """All certs in the output bundle should have unique fingerprints."""
        all_certs = [cac_cert, piv_cert, eca_cert, ca_cert]

        source_certs = data.draw(st.lists(st.sampled_from(all_certs), min_size=1, max_size=15))
        cert_lists = [("test_source", source_certs)]

        _pem_bundle, stats = merge_and_deduplicate(cert_lists)  # pem_bundle unused here

        # Count unique fingerprints in input
        unique_fps = set()
        for cert in source_certs:
            unique_fps.add(cert_fingerprint(cert))

        # Output total should equal number of unique fingerprints
        assert stats["total"] == len(unique_fps)

    def test_empty_input(self):
        """Empty input should produce empty output."""
        pem_bundle, stats = merge_and_deduplicate([])
        assert pem_bundle == ""
        assert stats["total"] == 0

    def test_single_cert(self, cac_cert):
        """Single cert should produce a bundle with exactly one cert."""
        pem_bundle, stats = merge_and_deduplicate([("src", [cac_cert])])
        assert isinstance(pem_bundle, str)
        assert len(pem_bundle) > 0
        assert stats["total"] == 1

    def test_all_duplicates(self, cac_cert):
        """Multiple copies of the same cert should deduplicate to one."""
        cert_lists = [("src", [cac_cert, cac_cert, cac_cert])]
        _pem_bundle, stats = merge_and_deduplicate(cert_lists)  # pem_bundle unused here
        assert stats["total"] == 1

    @given(data=st.data())
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_order_independence_of_count(self, data, cac_cert, piv_cert, eca_cert, ca_cert):
        """Total unique count should be the same regardless of input order."""
        all_certs = [cac_cert, piv_cert, eca_cert, ca_cert]

        certs_a = data.draw(st.lists(st.sampled_from(all_certs), min_size=1, max_size=10))
        certs_b = data.draw(st.permutations(certs_a))

        _, stats_a = merge_and_deduplicate([("a", certs_a)])
        _, stats_b = merge_and_deduplicate([("b", list(certs_b))])

        assert stats_a["total"] == stats_b["total"]

    @given(data=st.data())
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_multiple_sources_merge_correctly(self, data, cac_cert, piv_cert, eca_cert):
        """Certs split across sources should merge correctly."""
        all_certs = [cac_cert, piv_cert, eca_cert]

        source1 = data.draw(st.lists(st.sampled_from(all_certs), min_size=0, max_size=5))
        source2 = data.draw(st.lists(st.sampled_from(all_certs), min_size=0, max_size=5))

        cert_lists = [("source1", source1), ("source2", source2)]
        _, stats = merge_and_deduplicate(cert_lists)

        # Compute expected unique count
        unique_fps = set()
        for cert in source1 + source2:
            unique_fps.add(cert_fingerprint(cert))

        assert stats["total"] == len(unique_fps)

    def test_pem_bundle_contains_begin_certificate(self, cac_cert, piv_cert):
        """PEM bundle should contain BEGIN CERTIFICATE markers."""
        cert_lists = [("src", [cac_cert, piv_cert])]
        pem_bundle, stats = merge_and_deduplicate(cert_lists)
        assert pem_bundle.count("-----BEGIN CERTIFICATE-----") == stats["total"]

    def test_stats_source_counts(self, cac_cert, piv_cert, eca_cert):
        """Stats should correctly attribute certs to their sources."""
        cert_lists = [
            ("source_a", [cac_cert, piv_cert]),
            ("source_b", [eca_cert]),
        ]
        _, stats = merge_and_deduplicate(cert_lists)
        assert stats["total"] == 3
        assert stats.get("source_a", 0) == 2
        assert stats.get("source_b", 0) == 1
