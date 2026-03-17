"""Tests for pki.core.providers."""

import pytest

from pki.core.providers import AuthProvider, HeuristicRule, ProviderRegistry


def _noop_parser(identity):
    pass


def _dn_selector(identity):
    return f"dn:{identity.subject_dn}"


class TestProviderRegistry:
    def test_register_and_get(self):
        provider = AuthProvider(
            name="TEST",
            display_name="Test",
            auth_oids=frozenset({"1.2.3"}),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
        )
        reg = ProviderRegistry()
        reg.register(provider)
        assert reg.get("TEST") is provider
        assert len(reg) == 1

    def test_match_oids(self):
        provider = AuthProvider(
            name="TEST",
            display_name="Test",
            auth_oids=frozenset({"1.2.3", "4.5.6"}),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
        )
        reg = ProviderRegistry()
        reg.register(provider)
        assert reg.match_oids({"1.2.3"}) is provider
        assert reg.match_oids({"9.9.9"}) is None

    def test_match_heuristic_substring(self):
        provider = AuthProvider(
            name="TEST",
            display_name="Test",
            auth_oids=frozenset(),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
            heuristics=(HeuristicRule(field="org", pattern="acme"),),
        )
        reg = ProviderRegistry()
        reg.register(provider)
        assert reg.match_heuristic(None, "ACME Corp", None) is provider
        assert reg.match_heuristic(None, "Other Corp", None) is None

    def test_match_heuristic_regex(self):
        provider = AuthProvider(
            name="TEST",
            display_name="Test",
            auth_oids=frozenset(),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
            heuristics=(HeuristicRule(field="cn", pattern=r"^[A-Z]+\.\d+$", is_regex=True),),
        )
        reg = ProviderRegistry()
        reg.register(provider)
        assert reg.match_heuristic("SMITH.1234567890", None, None) is provider
        assert reg.match_heuristic("smith", None, None) is None

    def test_invalid_regex_raises(self):
        provider = AuthProvider(
            name="BAD",
            display_name="Bad",
            auth_oids=frozenset(),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
            heuristics=(HeuristicRule(field="cn", pattern="[invalid", is_regex=True),),
        )
        reg = ProviderRegistry()
        with pytest.raises(ValueError, match="Invalid regex"):
            reg.register(provider)

    def test_empty_registry(self):
        reg = ProviderRegistry()
        assert len(reg) == 0
        assert reg.match_oids({"1.2.3"}) is None
        assert reg.all() == []
