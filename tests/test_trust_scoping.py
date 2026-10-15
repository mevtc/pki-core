"""Trust-anchor scoping: roots vs intermediates, provider pins, trust domains,
and revocation across the validated chain.

The fixture mirrors the Federal PKI shape that motivated it::

    Root (self-signed)
     └─ Bridge             cross-cert, critical policyConstraints/inhibitAnyPolicy
         └─ Member Root    cross-cert issued by the bridge (e.g. one PIV-I issuer)
             └─ Issuing CA
                 └─ leaf
"""

from __future__ import annotations

import datetime as dt
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pki.core.certificate import CertificateError, cert_fingerprint, is_self_signed
from pki.core.identity import parse_identity
from pki.core.providers import AuthProvider, ProviderRegistry
from pki.core.revocation import RevocationPolicy
from pki.core.selectors import select_uuid_first
from pki.core.validation import (
    CertificatePolicy,
    ValidationStatus,
    split_trust_anchors,
    validate_certificate,
    verify_chain,
)

NOW = dt.datetime.now(dt.UTC)
POLICY_OID = "2.16.840.1.101.3.2.1.3.13"
UUID = "12345678-abcd-ef01-2345-6789abcdef01"


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _crl_url(cn: str) -> str:
    return f"http://crl.test/{cn.replace(' ', '_')}.crl"


def _ca(subject, issuer, key, issuer_key, *, cross_cert=False, cdp=True):
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False
        )
    )
    if cross_cert:
        builder = builder.add_extension(
            x509.PolicyConstraints(require_explicit_policy=0, inhibit_policy_mapping=None),
            critical=True,
        ).add_extension(x509.InhibitAnyPolicy(0), critical=True)
    if cdp and subject != issuer:
        builder = builder.add_extension(_cdp(issuer), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def _cdp(issuer_cn: str) -> x509.CRLDistributionPoints:
    return x509.CRLDistributionPoints(
        [
            x509.DistributionPoint(
                [x509.UniformResourceIdentifier(_crl_url(issuer_cn))], None, None, None
            )
        ]
    )


def _crl(issuer_cn: str, key, revoked=()) -> bytes:
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(_name(issuer_cn))
        .last_update(NOW)
        .next_update(NOW + dt.timedelta(days=1))
    )
    for serial in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(NOW).build()
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


@pytest.fixture(scope="module")
def pki():
    keys = {
        n: ec.generate_private_key(ec.SECP256R1())
        for n in ("root", "bridge", "member", "issuing", "leaf")
    }
    root = _ca("Root", "Root", keys["root"], keys["root"])
    bridge = _ca("Bridge", "Root", keys["bridge"], keys["root"], cross_cert=True)
    member = _ca("Member Root", "Bridge", keys["member"], keys["bridge"], cross_cert=True)
    issuing = _ca("Issuing CA", "Member Root", keys["issuing"], keys["member"])
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("DOE.JANE"))
        .issuer_name(_name("Issuing CA"))
        .public_key(keys["leaf"].public_key())
        .serial_number(0x1EAF)
        .not_valid_before(NOW - dt.timedelta(days=1))
        .not_valid_after(NOW + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"urn:uuid:{UUID}")]),
            False,
        )
        .add_extension(
            x509.CertificatePolicies(
                [x509.PolicyInformation(x509.ObjectIdentifier(POLICY_OID), None)]
            ),
            False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(keys["issuing"].public_key()),
            False,
        )
        .add_extension(_cdp("Issuing CA"), False)
        .sign(keys["issuing"], hashes.SHA256())
    )
    return {
        "keys": keys,
        "root": root,
        "bridge": bridge,
        "member": member,
        "issuing": issuing,
        "leaf": leaf,
    }


def _provider(pki, *, pins=None, bridges=frozenset({"CN=Bridge"})):
    return AuthProvider(
        name="PIV",
        display_name="Test PIV",
        auth_oids=frozenset({POLICY_OID}),
        cn_parser=lambda identity: None,
        primary_id_selector=select_uuid_first,
        trust_anchor_fingerprints=(
            frozenset({cert_fingerprint(pki["root"])}) if pins is None else pins
        ),
        bridge_ca_subjects=bridges,
    )


def _registry(provider):
    reg = ProviderRegistry()
    reg.register(provider)
    return reg


def _flat_store(pki):
    """Everything in one flat list, the way a downloaded CA bundle arrives."""
    return [pki["root"], pki["bridge"], pki["member"], pki["issuing"]]


def _crls(pki, revoked_by=None):
    """CRL bytes per URL; *revoked_by* maps issuer CN -> serials it revokes."""
    revoked_by = revoked_by or {}
    k = pki["keys"]
    return {
        _crl_url(cn): _crl(cn, key, revoked_by.get(cn, ()))
        for cn, key in (
            ("Root", k["root"]),
            ("Bridge", k["bridge"]),
            ("Member Root", k["member"]),
            ("Issuing CA", k["issuing"]),
        )
    }


def _serve(crls):
    return patch("pki.core.crl.fetch_bytes", side_effect=lambda url, **kw: crls[url])


def _policy(pki, tmp_path, provider, **kw):
    from pki.core.crl import CRLConfig

    return CertificatePolicy(
        check_chain=True,
        trust_store=_flat_store(pki),
        registry=_registry(provider),
        revocation=RevocationPolicy(crl_config=CRLConfig(cache_dir=str(tmp_path))),
        **kw,
    )


class TestRootsAndIntermediates:
    def test_is_self_signed(self, pki):
        assert is_self_signed(pki["root"])
        assert not is_self_signed(pki["bridge"])

    def test_same_name_different_key_is_not_self_signed(self, pki):
        impostor = _ca("Root", "Root", pki["keys"]["leaf"], pki["keys"]["root"])
        assert not is_self_signed(impostor)

    def test_split(self, pki):
        roots, intermediates = split_trust_anchors(_flat_store(pki))
        assert roots == [pki["root"]]
        assert intermediates == [pki["bridge"], pki["member"], pki["issuing"]]

    def test_bridged_path_validates_to_root(self, pki):
        chain = verify_chain(pki["leaf"], _flat_store(pki))
        assert chain[-1] == pki["root"]
        assert len(chain) == 5

    def test_cross_cert_alone_is_not_an_anchor(self, pki):
        """Regression: a flat bundle used to make every cross-cert a root."""
        with pytest.raises(CertificateError, match="no self-signed root"):
            verify_chain(pki["leaf"], [pki["member"], pki["issuing"]])


class TestProviderScoping:
    def test_primary_id_is_provider_and_domain_scoped(self, pki, tmp_path):
        with _serve(_crls(pki)):
            result = validate_certificate(pki["leaf"], _policy(pki, tmp_path, _provider(pki)))
        assert result.status == ValidationStatus.VALID, result.error
        assert result.identity.trust_domain == "CN=Member Root"
        assert result.identity.trust_anchor == cert_fingerprint(pki["root"])
        assert result.identity.primary_id == f"PIV[CN=Member Root]:uuid:{UUID}"

    def test_no_bridge_declared_scopes_to_provider_only(self, pki):
        chain = verify_chain(pki["leaf"], _flat_store(pki))
        identity = parse_identity(
            pki["leaf"], _registry(_provider(pki, bridges=frozenset())), chain
        )
        assert identity.trust_domain is None
        assert identity.primary_id == f"PIV:uuid:{UUID}"

    def test_without_chain_scopes_to_provider_only(self, pki):
        identity = parse_identity(pki["leaf"], _registry(_provider(pki)))
        assert identity.trust_anchor is None
        assert identity.primary_id == f"PIV:uuid:{UUID}"

    def test_unmatched_cert_scoped_by_issuer(self, pki):
        identity = parse_identity(pki["leaf"], ProviderRegistry())
        assert identity.primary_id == "dn:CN=Issuing CA;CN=DOE.JANE"

    def test_chain_to_unpinned_root_rejected(self, pki, tmp_path):
        provider = _provider(pki, pins=frozenset({"00" * 32}))
        with _serve(_crls(pki)):
            result = validate_certificate(pki["leaf"], _policy(pki, tmp_path, provider))
        assert result.status == ValidationStatus.CHAIN_UNTRUSTED
        assert "not a trust anchor for provider 'PIV'" in result.error


class TestChainRevocation:
    def test_revoked_intermediate_rejected(self, pki, tmp_path):
        crls = _crls(pki, revoked_by={"Bridge": [pki["member"].serial_number]})
        with _serve(crls):
            result = validate_certificate(pki["leaf"], _policy(pki, tmp_path, _provider(pki)))
        assert result.status == ValidationStatus.REVOKED
        assert "Chain certificate CN=Member Root" in result.error

    def test_revoked_leaf_rejected(self, pki, tmp_path):
        crls = _crls(pki, revoked_by={"Issuing CA": [pki["leaf"].serial_number]})
        with _serve(crls):
            result = validate_certificate(pki["leaf"], _policy(pki, tmp_path, _provider(pki)))
        assert result.status == ValidationStatus.REVOKED

    def test_crl_verified_against_actual_issuer(self, pki, tmp_path):
        """A CRL naming the right issuer but signed by another key is refused,
        even though the caller supplied no issuer_certs."""
        crls = _crls(pki)
        crls[_crl_url("Issuing CA")] = _crl("Issuing CA", pki["keys"]["leaf"])
        with _serve(crls):
            result = validate_certificate(pki["leaf"], _policy(pki, tmp_path, _provider(pki)))
        assert result.status == ValidationStatus.ERROR
        assert "signature verification failed" in result.error

    def test_every_non_root_certificate_checked(self, pki, tmp_path):
        crls = _crls(pki)
        fetched = []

        def fetch(url, **kw):
            fetched.append(url)
            return crls[url]

        with patch("pki.core.crl.fetch_bytes", side_effect=fetch):
            validate_certificate(pki["leaf"], _policy(pki, tmp_path, _provider(pki)))
        assert sorted(fetched) == sorted(
            _crl_url(cn) for cn in ("Root", "Bridge", "Member Root", "Issuing CA")
        )
