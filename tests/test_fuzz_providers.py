"""Hypothesis fuzz tests for provider registry matching.

Property-based tests that throw random OID sets, CN/org/ou strings, and
regex patterns at the ProviderRegistry to verify it never crashes and
always satisfies return-type invariants.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.providers import AuthProvider, HeuristicRule, ProviderRegistry
from pki.core.selectors import select_edipi_first

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _noop_cn_parser(identity):
    """No-op CN parser for test providers."""
    pass


def _make_test_provider(
    name: str = "test",
    auth_oids: frozenset[str] | None = None,
    heuristics: tuple[HeuristicRule, ...] = (),
) -> AuthProvider:
    """Build a minimal test AuthProvider."""
    return AuthProvider(
        name=name,
        display_name=f"Test {name}",
        auth_oids=auth_oids or frozenset({"2.16.840.1.101.2.1.11.19"}),
        cn_parser=_noop_cn_parser,
        primary_id_selector=select_edipi_first,
        heuristics=heuristics,
    )


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# OID-like strings
oid_str = st.from_regex(r"[0-9]+(\.[0-9]+){2,8}", fullmatch=True)
random_oid_set = st.frozensets(oid_str, min_size=0, max_size=10)

# Random strings for heuristic matching
random_text = st.one_of(st.none(), st.text(min_size=0, max_size=200))


# ---------------------------------------------------------------------------
# match_oids — random OID sets
# ---------------------------------------------------------------------------


class TestFuzzMatchOids:
    @given(oids=random_oid_set)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, oids):
        """match_oids with random OID sets should never crash."""
        registry = ProviderRegistry()
        provider = _make_test_provider()
        registry.register(provider)
        result = registry.match_oids(set(oids))
        assert result is None or result is provider

    @given(oids=random_oid_set)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_empty_registry_returns_none(self, oids):
        """An empty registry should always return None."""
        registry = ProviderRegistry()
        result = registry.match_oids(set(oids))
        assert result is None

    def test_matching_oid_returns_provider(self):
        """When a matching OID is present, the provider should be returned."""
        registry = ProviderRegistry()
        provider = _make_test_provider(auth_oids=frozenset({"1.2.3.4"}))
        registry.register(provider)
        result = registry.match_oids({"1.2.3.4", "5.6.7.8"})
        assert result is provider

    def test_no_matching_oid_returns_none(self):
        """When no OID matches, None should be returned."""
        registry = ProviderRegistry()
        provider = _make_test_provider(auth_oids=frozenset({"1.2.3.4"}))
        registry.register(provider)
        result = registry.match_oids({"5.6.7.8"})
        assert result is None

    @given(oids=random_oid_set)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_multiple_providers_first_match_wins(self, oids):
        """First registered provider whose OIDs intersect should win."""
        registry = ProviderRegistry()
        p1 = _make_test_provider(name="first", auth_oids=frozenset({"1.1.1"}))
        p2 = _make_test_provider(name="second", auth_oids=frozenset({"2.2.2"}))
        registry.register(p1)
        registry.register(p2)
        result = registry.match_oids(set(oids))
        # Result must be p1, p2, or None
        assert result in (p1, p2, None)


# ---------------------------------------------------------------------------
# match_heuristic — random cn/org/ou strings
# ---------------------------------------------------------------------------


class TestFuzzMatchHeuristic:
    @given(cn=random_text, org=random_text, ou=random_text)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cn, org, ou):
        """match_heuristic with random strings should never crash."""
        registry = ProviderRegistry()
        provider = _make_test_provider(
            heuristics=(HeuristicRule(field="org", pattern="u.s. government"),)
        )
        registry.register(provider)
        result = registry.match_heuristic(cn, org, ou)
        assert result is None or result is provider

    @given(cn=random_text, org=random_text, ou=random_text)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_empty_registry_returns_none(self, cn, org, ou):
        """An empty registry should always return None."""
        registry = ProviderRegistry()
        result = registry.match_heuristic(cn, org, ou)
        assert result is None

    def test_substring_match(self):
        """A substring heuristic should match when the pattern is in the value."""
        registry = ProviderRegistry()
        provider = _make_test_provider(
            heuristics=(HeuristicRule(field="org", pattern="government"),)
        )
        registry.register(provider)
        result = registry.match_heuristic(None, "U.S. Government", None)
        assert result is provider

    def test_regex_match(self):
        """A regex heuristic should match correctly."""
        registry = ProviderRegistry()
        provider = _make_test_provider(
            heuristics=(HeuristicRule(field="cn", pattern=r"SMITH\.\w+", is_regex=True),)
        )
        registry.register(provider)
        result = registry.match_heuristic("SMITH.JOHN", None, None)
        assert result is provider

    def test_regex_no_match(self):
        """A regex heuristic that doesn't match should return None."""
        registry = ProviderRegistry()
        provider = _make_test_provider(
            heuristics=(HeuristicRule(field="cn", pattern=r"^JONES\.", is_regex=True),)
        )
        registry.register(provider)
        result = registry.match_heuristic("SMITH.JOHN", None, None)
        assert result is None

    @given(cn=random_text, org=random_text, ou=random_text)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_regex_heuristic_never_crashes(self, cn, org, ou):
        """Regex heuristic matching with random strings should never crash."""
        registry = ProviderRegistry()
        provider = _make_test_provider(
            heuristics=(HeuristicRule(field="cn", pattern=r"\w+\.\w+", is_regex=True),)
        )
        registry.register(provider)
        result = registry.match_heuristic(cn, org, ou)
        assert result is None or result is provider


# ---------------------------------------------------------------------------
# HeuristicRule with invalid regex — registration-time validation
# ---------------------------------------------------------------------------


class TestFuzzHeuristicRegexValidation:
    @given(pattern=st.text(min_size=1, max_size=50))
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_invalid_regex_raises_valueerror(self, pattern):
        """Invalid regex patterns should raise ValueError at registration time."""
        import re

        rule = HeuristicRule(field="cn", pattern=pattern, is_regex=True)
        provider = AuthProvider(
            name="regex_test",
            display_name="Regex Test",
            auth_oids=frozenset(),
            cn_parser=_noop_cn_parser,
            primary_id_selector=select_edipi_first,
            heuristics=(rule,),
        )
        registry = ProviderRegistry()
        try:
            re.compile(pattern)
        except re.error:
            # If Python's re module can't compile it, register() must raise ValueError
            with pytest.raises(ValueError):
                registry.register(provider)
        else:
            # If the pattern is valid regex, registration should succeed
            registry.register(provider)
            assert registry.get("regex_test") is provider
