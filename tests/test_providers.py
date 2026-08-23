"""Tests for pki.core.providers."""

import pytest

from pki.core.providers import (
    _USE_PRECEDENCE,
    AuthProvider,
    HeuristicRule,
    IntendedUse,
    ProviderRegistry,
)


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


class TestMatchOidsPrecedence:
    """Resolution across use classes must not depend on registration order.

    DoD CP v11 Section 1.2: "All NPE certificates shall assert the appropriate
    Internal NPE or Medium NPE OID.  Medium NPE certificates may also assert
    any Medium Software or Medium Hardware OID if they meet the corresponding
    requirements."  A device certificate can therefore carry a person OID too,
    and first-match-wins would let dict insertion order decide whether it
    authenticates as a device or as a human.
    """

    def _provider(self, name, oids, use):
        return AuthProvider(
            name=name,
            display_name=name,
            auth_oids=frozenset(oids),
            cn_parser=_noop_parser,
            primary_id_selector=_dn_selector,
            intended_use=use,
        )

    def _dual_registry(self, person_first: bool):
        person = self._provider("PERSON", {"1.1", "shared"}, IntendedUse.PERSONAL_AUTH)
        device = self._provider("DEVICE", {"2.2", "shared"}, IntendedUse.NPE_AUTH)
        reg = ProviderRegistry()
        for p in (person, device) if person_first else (device, person):
            reg.register(p)
        return reg

    def test_device_wins_regardless_of_registration_order(self):
        for person_first in (True, False):
            reg = self._dual_registry(person_first)
            matched = reg.match_oids({"1.1", "2.2"})
            assert matched is not None
            assert matched.intended_use is IntendedUse.NPE_AUTH, (
                f"person_first={person_first} resolved to {matched.name}"
            )

    def test_card_auth_outranks_person(self):
        reg = ProviderRegistry()
        reg.register(self._provider("PERSON", {"1.1"}, IntendedUse.PERSONAL_AUTH))
        reg.register(self._provider("CARD", {"2.2"}, IntendedUse.CARD_AUTH))
        assert reg.match_oids({"1.1", "2.2"}).intended_use is IntendedUse.CARD_AUTH

    def test_card_auth_outranks_device(self):
        reg = ProviderRegistry()
        reg.register(self._provider("DEVICE", {"1.1"}, IntendedUse.NPE_AUTH))
        reg.register(self._provider("CARD", {"2.2"}, IntendedUse.CARD_AUTH))
        assert reg.match_oids({"1.1", "2.2"}).intended_use is IntendedUse.CARD_AUTH

    def test_unambiguous_match_still_honours_order(self):
        """Same use class: first registered wins, as before."""
        reg = ProviderRegistry()
        reg.register(self._provider("FIRST", {"1.1"}, IntendedUse.PERSONAL_AUTH))
        reg.register(self._provider("SECOND", {"1.1"}, IntendedUse.PERSONAL_AUTH))
        assert reg.match_oids({"1.1"}).name == "FIRST"

    def test_single_class_match_unchanged(self):
        reg = self._dual_registry(person_first=True)
        assert reg.match_oids({"1.1"}).name == "PERSON"
        assert reg.match_oids({"2.2"}).name == "DEVICE"

    def test_no_match_returns_none(self):
        reg = self._dual_registry(person_first=True)
        assert reg.match_oids({"9.9"}) is None

    def test_person_is_only_reachable_when_nothing_narrower_matched(self):
        """PERSONAL_AUTH is last in the precedence list, by design."""
        assert _USE_PRECEDENCE[-1] is IntendedUse.PERSONAL_AUTH
        assert _USE_PRECEDENCE[0] is IntendedUse.CARD_AUTH

    def test_unknown_use_combination_fails_closed(self):
        """A use class outside the precedence list must not silently resolve."""
        odd = IntendedUse.PERSONAL_AUTH | IntendedUse.NPE_AUTH
        reg = ProviderRegistry()
        reg.register(self._provider("COMBO", {"1.1"}, odd))
        reg.register(self._provider("PERSON", {"2.2"}, IntendedUse.PERSONAL_AUTH))
        # COMBO's composite flag matches no single precedence entry; PERSON does,
        # so resolution must land on PERSON rather than the composite.
        matched = reg.match_oids({"1.1", "2.2"})
        assert matched is None or matched.intended_use is IntendedUse.PERSONAL_AUTH
