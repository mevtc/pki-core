"""Tests for pki.core.providers."""

import pytest

from pki.core.providers import AuthProvider, HeuristicRule, IntendedUse, ProviderRegistry


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


class TestIntendedUseConstraint:
    def _provider(self, name: str, intended_use: IntendedUse) -> AuthProvider:
        return AuthProvider(
            name=name,
            display_name=name,
            auth_oids=frozenset({"1.2.3"}),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
            intended_use=intended_use,
        )

    def test_default_intended_use_is_personal_auth(self):
        provider = AuthProvider(
            name="DEFAULT",
            display_name="Default",
            auth_oids=frozenset(),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
        )
        assert provider.intended_use is IntendedUse.PERSONAL_AUTH

    def test_unconstrained_registry_accepts_anything(self):
        reg = ProviderRegistry()
        reg.register(self._provider("PE", IntendedUse.PERSONAL_AUTH))
        reg.register(self._provider("CS", IntendedUse.OBJECT_SIGNING))
        assert len(reg) == 2

    def test_constrained_registry_accepts_matching(self):
        reg = ProviderRegistry(intended_use=IntendedUse.PERSONAL_AUTH)
        reg.register(self._provider("PE", IntendedUse.PERSONAL_AUTH))
        assert len(reg) == 1

    def test_constrained_registry_rejects_mismatched(self):
        reg = ProviderRegistry(intended_use=IntendedUse.PERSONAL_AUTH)
        cs = self._provider("CS", IntendedUse.OBJECT_SIGNING)
        with pytest.raises(ValueError, match="does not support"):
            reg.register(cs)

    def test_constrained_registry_accepts_multi_use_provider(self):
        """Provider with multiple bits set passes if constraint bits are present."""
        reg = ProviderRegistry(intended_use=IntendedUse.PERSONAL_AUTH)
        multi = self._provider("MULTI", IntendedUse.PERSONAL_AUTH | IntendedUse.OBJECT_SIGNING)
        reg.register(multi)
        assert len(reg) == 1

    def test_intended_use_set_membership(self):
        """The boundary check authn-* will use."""
        pe_only = self._provider("PE", IntendedUse.PERSONAL_AUTH)
        cs_only = self._provider("CS", IntendedUse.OBJECT_SIGNING)
        assert IntendedUse.PERSONAL_AUTH in pe_only.intended_use
        assert IntendedUse.PERSONAL_AUTH not in cs_only.intended_use


class TestCardAuthIsolation:
    """CARD_AUTH must not satisfy person or device authentication.

    A card-authentication key needs no activation data, so validating one
    proves the token is present and nothing about who holds it.  On a real
    card it can share a subject identifier with the personal-authentication
    certificate, so any leak across this boundary lets a PIN-less read
    authenticate as the cardholder.
    """

    def _provider(self, name: str, intended_use: IntendedUse) -> AuthProvider:
        return AuthProvider(
            name=name,
            display_name=name,
            auth_oids=frozenset({"1.2.3"}),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
            intended_use=intended_use,
        )

    def test_card_auth_is_a_distinct_bit(self):
        assert IntendedUse.CARD_AUTH is not IntendedUse.PERSONAL_AUTH
        assert IntendedUse.CARD_AUTH is not IntendedUse.NPE_AUTH

    def test_card_auth_does_not_satisfy_personal_or_npe(self):
        card = self._provider("CARD", IntendedUse.CARD_AUTH)
        assert IntendedUse.PERSONAL_AUTH not in card.intended_use
        assert IntendedUse.NPE_AUTH not in card.intended_use
        assert IntendedUse.CARD_AUTH in card.intended_use

    def test_person_provider_does_not_satisfy_card_auth(self):
        pe = self._provider("PE", IntendedUse.PERSONAL_AUTH)
        assert IntendedUse.CARD_AUTH not in pe.intended_use

    def test_person_constrained_registry_rejects_card_auth(self):
        """A person-only registry must refuse a card-auth provider outright."""
        reg = ProviderRegistry(intended_use=IntendedUse.PERSONAL_AUTH)
        with pytest.raises(ValueError, match="does not support"):
            reg.register(self._provider("CARD", IntendedUse.CARD_AUTH))

    def test_npe_constrained_registry_rejects_card_auth(self):
        reg = ProviderRegistry(intended_use=IntendedUse.NPE_AUTH)
        with pytest.raises(ValueError, match="does not support"):
            reg.register(self._provider("CARD", IntendedUse.CARD_AUTH))
