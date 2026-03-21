"""Hypothesis fuzz tests for identity extraction and selector functions.

Property-based tests that throw random inputs at parse_identity() and
the selector functions to verify they never crash and always satisfy
return-type and field-type invariants.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.identity import CertIdentity, parse_identity
from pki.core.providers import ProviderRegistry
from pki.core.selectors import select_edipi_first, select_email_first, select_uuid_first

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Random strings for identity fields (including None)
optional_str = st.one_of(st.none(), st.text(min_size=0, max_size=100))
non_none_str = st.text(min_size=1, max_size=100)

random_identity = st.builds(
    CertIdentity,
    cn=optional_str,
    firstname=optional_str,
    lastname=optional_str,
    edipi=optional_str,
    piv_uuid=optional_str,
    fascn=optional_str,
    email=optional_str,
    subject_dn=optional_str,
    organization=optional_str,
    ou=optional_str,
    cert_serial=optional_str,
    cert_not_after=optional_str,
    cert_issuer_dn=optional_str,
    primary_id=optional_str,
    credential_type=optional_str,
    policy_oids=st.lists(st.text(min_size=1, max_size=30), max_size=5),
)


# ---------------------------------------------------------------------------
# parse_identity — real certs from fixtures
# ---------------------------------------------------------------------------


class TestFuzzParseIdentity:
    """parse_identity() should always return a CertIdentity with correct field types."""

    _STR_FIELDS = (
        "primary_id",
        "credential_type",
        "cn",
        "firstname",
        "lastname",
        "organization",
        "ou",
        "email",
        "edipi",
        "piv_uuid",
        "fascn",
        "cert_serial",
        "cert_not_after",
        "cert_issuer_dn",
        "subject_dn",
    )

    def _assert_identity_invariants(self, identity: CertIdentity) -> None:
        """Verify all field-type invariants on a CertIdentity."""
        assert isinstance(identity, CertIdentity)
        for field_name in self._STR_FIELDS:
            value = getattr(identity, field_name)
            assert value is None or isinstance(value, str), (
                f"{field_name} should be str|None, got {type(value)}"
            )
        assert isinstance(identity.policy_oids, list)
        for oid in identity.policy_oids:
            assert isinstance(oid, str)

    def test_cac_cert(self, cac_cert):
        identity = parse_identity(cac_cert)
        self._assert_identity_invariants(identity)

    def test_cac_cert_with_registry(self, cac_cert):
        identity = parse_identity(cac_cert, ProviderRegistry())
        self._assert_identity_invariants(identity)

    def test_piv_cert(self, piv_cert):
        identity = parse_identity(piv_cert)
        self._assert_identity_invariants(identity)

    def test_eca_cert(self, eca_cert):
        identity = parse_identity(eca_cert)
        self._assert_identity_invariants(identity)

    def test_expired_cert(self, expired_cert):
        identity = parse_identity(expired_cert)
        self._assert_identity_invariants(identity)

    def test_ca_cert(self, ca_cert):
        identity = parse_identity(ca_cert)
        self._assert_identity_invariants(identity)

    def test_all_certs_have_subject_dn(self, cac_cert, piv_cert, eca_cert, expired_cert, ca_cert):
        """Every valid certificate should produce a non-None subject_dn."""
        for cert in (cac_cert, piv_cert, eca_cert, expired_cert, ca_cert):
            identity = parse_identity(cert)
            assert identity.subject_dn is not None
            assert isinstance(identity.subject_dn, str)
            assert len(identity.subject_dn) > 0

    def test_all_certs_have_cert_serial(self, cac_cert, piv_cert, eca_cert):
        """Every valid certificate should produce a non-None cert_serial."""
        for cert in (cac_cert, piv_cert, eca_cert):
            identity = parse_identity(cert)
            assert identity.cert_serial is not None
            assert isinstance(identity.cert_serial, str)

    def test_to_dict_returns_dict(self, cac_cert):
        """CertIdentity.to_dict() should always return a dict."""
        identity = parse_identity(cac_cert)
        d = identity.to_dict()
        assert isinstance(d, dict)
        assert "primary_id" in d
        assert "policy_oids" in d


# ---------------------------------------------------------------------------
# Selector functions — random CertIdentity objects
# ---------------------------------------------------------------------------


class TestFuzzSelectEdpiFirst:
    @given(identity=random_identity)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_always_returns_string(self, identity):
        """select_edipi_first should always return a str, never crash."""
        result = select_edipi_first(identity)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(edipi=non_none_str)
    def test_edipi_takes_priority(self, edipi):
        """If edipi is set, it should be returned regardless of other fields."""
        identity = CertIdentity(
            edipi=edipi,
            piv_uuid="some-uuid",
            fascn="some-fascn",
            subject_dn="CN=test",
        )
        result = select_edipi_first(identity)
        assert result == f"edipi:{edipi}"

    def test_falls_through_to_uuid(self):
        identity = CertIdentity(piv_uuid="test-uuid", fascn="test-fascn", subject_dn="CN=test")
        result = select_edipi_first(identity)
        assert result == "uuid:test-uuid"

    def test_falls_through_to_fascn(self):
        identity = CertIdentity(fascn="test-fascn", subject_dn="CN=test")
        result = select_edipi_first(identity)
        assert result == "fascn:test-fascn"

    def test_falls_through_to_dn(self):
        identity = CertIdentity(subject_dn="CN=test")
        result = select_edipi_first(identity)
        assert result == "dn:CN=test"


class TestFuzzSelectUuidFirst:
    @given(identity=random_identity)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_always_returns_string(self, identity):
        """select_uuid_first should always return a str, never crash."""
        result = select_uuid_first(identity)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(uuid=non_none_str)
    def test_uuid_takes_priority(self, uuid):
        """If piv_uuid is set, it should be returned regardless of other fields."""
        identity = CertIdentity(
            edipi="some-edipi",
            piv_uuid=uuid,
            fascn="some-fascn",
            subject_dn="CN=test",
        )
        result = select_uuid_first(identity)
        assert result == f"uuid:{uuid}"

    def test_falls_through_to_fascn(self):
        identity = CertIdentity(fascn="test-fascn", edipi="test-edipi", subject_dn="CN=test")
        result = select_uuid_first(identity)
        assert result == "fascn:test-fascn"

    def test_falls_through_to_edipi(self):
        identity = CertIdentity(edipi="test-edipi", subject_dn="CN=test")
        result = select_uuid_first(identity)
        assert result == "edipi:test-edipi"

    def test_falls_through_to_dn(self):
        identity = CertIdentity(subject_dn="CN=test")
        result = select_uuid_first(identity)
        assert result == "dn:CN=test"


class TestFuzzSelectEmailFirst:
    @given(identity=random_identity)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_always_returns_string(self, identity):
        """select_email_first should always return a str, never crash."""
        result = select_email_first(identity)
        assert isinstance(result, str)
        assert len(result) > 0

    @given(email=non_none_str)
    def test_email_takes_priority(self, email):
        """If email is set, it should be returned regardless of other fields."""
        identity = CertIdentity(email=email, subject_dn="CN=test")
        result = select_email_first(identity)
        assert result == f"email:{email}"

    def test_falls_through_to_dn(self):
        identity = CertIdentity(subject_dn="CN=test")
        result = select_email_first(identity)
        assert result == "dn:CN=test"
