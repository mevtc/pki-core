"""Tests for pki.core.identity."""

from pki.core.identity import parse_identity
from pki.core.providers import AuthProvider, IntendedUse, ProviderRegistry


def _test_parser(identity):
    if identity.cn and "." in identity.cn:
        parts = identity.cn.split(".")
        identity.lastname = parts[0]
        identity.firstname = parts[1] if len(parts) > 1 else None
        if len(parts) >= 4 and parts[-1].isdigit():
            identity.edipi = parts[-1]


def _test_selector(identity):
    if identity.edipi:
        return f"edipi:{identity.edipi}"
    return f"dn:{identity.subject_dn}"


class TestParseIdentityEmptyRegistry:
    def test_unknown_credential_type(self, cac_cert):
        identity = parse_identity(cac_cert)
        assert identity.credential_type == "UNKNOWN"
        assert identity.primary_id.startswith("dn:")

    def test_unknown_credential_has_no_intended_use(self, cac_cert):
        identity = parse_identity(cac_cert)
        assert identity.intended_use is None

    def test_basic_fields_populated(self, cac_cert):
        identity = parse_identity(cac_cert)
        assert identity.cn == "SMITH.JOHN.A.1234567890"
        assert identity.cert_serial is not None
        assert identity.subject_dn is not None


class TestParseIdentityNoMatch:
    def test_unknown_when_oid_and_heuristics_miss(self, cac_cert):
        """Registered provider whose OIDs and heuristics both miss must
        not be selected as a silent fallback — credential_type is UNKNOWN."""
        provider = AuthProvider(
            name="MISMATCHED",
            display_name="Mismatched",
            auth_oids=frozenset({"9.9.9.9.9"}),
            cn_parser=_test_parser,
            primary_id_selector=_test_selector,
        )
        reg = ProviderRegistry()
        reg.register(provider)

        identity = parse_identity(cac_cert, registry=reg)
        assert identity.credential_type == "UNKNOWN"


class TestParseIdentityWithProvider:
    def test_custom_provider(self, cac_cert):
        provider = AuthProvider(
            name="TEST_CAC",
            display_name="Test CAC",
            auth_oids=frozenset({"2.16.840.1.101.2.1.11.19"}),
            cn_parser=_test_parser,
            primary_id_selector=_test_selector,
        )
        reg = ProviderRegistry()
        reg.register(provider)

        identity = parse_identity(cac_cert, registry=reg)
        assert identity.credential_type == "TEST_CAC"
        assert identity.lastname == "SMITH"
        assert identity.firstname == "JOHN"
        assert identity.edipi == "1234567890"
        assert identity.primary_id == "edipi:1234567890"

    def test_default_intended_use_is_personal_auth(self, cac_cert):
        provider = AuthProvider(
            name="TEST_CAC",
            display_name="Test CAC",
            auth_oids=frozenset({"2.16.840.1.101.2.1.11.19"}),
            cn_parser=_test_parser,
            primary_id_selector=_test_selector,
        )
        reg = ProviderRegistry()
        reg.register(provider)

        identity = parse_identity(cac_cert, registry=reg)
        assert identity.intended_use is IntendedUse.PERSONAL_AUTH

    def test_intended_use_reflects_matched_provider(self, cac_cert):
        provider = AuthProvider(
            name="TEST_NPE",
            display_name="Test NPE",
            auth_oids=frozenset({"2.16.840.1.101.2.1.11.19"}),
            cn_parser=_test_parser,
            primary_id_selector=_test_selector,
            intended_use=IntendedUse.NPE_AUTH | IntendedUse.OBJECT_SIGNING,
        )
        reg = ProviderRegistry()
        reg.register(provider)

        identity = parse_identity(cac_cert, registry=reg)
        assert identity.intended_use == (IntendedUse.NPE_AUTH | IntendedUse.OBJECT_SIGNING)
        assert IntendedUse.PERSONAL_AUTH not in identity.intended_use
