"""Certificate identity extraction.

Extracts structured identity information from x509 certificates using
a pluggable provider registry for CN parsing and primary ID selection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import NameOID

from .certificate import (
    cert_fingerprint,
    extract_email,
    extract_san_fascn,
    extract_san_uuid,
    get_name_attr,
    get_policy_oids,
)
from .providers import AuthProvider, IntendedUse, MatchOutcome, ProviderRegistry
from .selectors import scoped_dn


@dataclass
class CertIdentity:
    """Parsed identity from a client certificate."""

    primary_id: str | None = None
    credential_type: str | None = None
    # Informational only — parse_identity() does not reject a cert whose
    # matched provider's intended_use is unexpected. Callers that need to
    # enforce a use (e.g. reject non-personal-auth certs) must check this
    # field themselves or constrain the ProviderRegistry they pass in.
    intended_use: IntendedUse | None = None
    cn: str | None = None
    firstname: str | None = None
    lastname: str | None = None
    organization: str | None = None
    ou: str | None = None
    email: str | None = None
    edipi: str | None = None
    piv_uuid: str | None = None
    fascn: str | None = None
    cert_serial: str | None = None
    cert_not_after: str | None = None
    cert_issuer_dn: str | None = None
    subject_dn: str | None = None
    policy_oids: list[str] = field(default_factory=list)
    # Set only when parse_identity() is given the validated chain.
    trust_anchor: str | None = None  # SHA-256 fingerprint of the chain's root
    trust_domain: str | None = None  # cross-certified root below a bridge, if any

    def to_dict(self) -> dict:
        """Convert identity fields to a plain dictionary."""
        return {
            "primary_id": self.primary_id,
            "credential_type": self.credential_type,
            "intended_use": self.intended_use.name if self.intended_use else None,
            "cn": self.cn,
            "firstname": self.firstname,
            "lastname": self.lastname,
            "organization": self.organization,
            "ou": self.ou,
            "email": self.email,
            "edipi": self.edipi,
            "piv_uuid": self.piv_uuid,
            "fascn": self.fascn,
            "cert_serial": self.cert_serial,
            "cert_not_after": self.cert_not_after,
            "cert_issuer_dn": self.cert_issuer_dn,
            "subject_dn": self.subject_dn,
            "policy_oids": self.policy_oids,
            "trust_anchor": self.trust_anchor,
            "trust_domain": self.trust_domain,
        }


def _trust_domain(chain: list[x509.Certificate], bridges: frozenset[str]) -> str | None:
    """Return the subject of the first non-bridge CA issued by a bridge.

    Walks from the anchor towards the leaf.  ``None`` means the chain never
    crossed a bridge, so the anchor itself is the domain.
    """
    for ca in reversed(chain[1:-1]):
        subject = ca.subject.rfc4514_string()
        if ca.issuer.rfc4514_string() in bridges and subject not in bridges:
            return subject
    return None


def _scoped_primary_id(provider: AuthProvider, identity: CertIdentity) -> str:
    """Prefix the provider's identifier with its namespace.

    ``CAC:edipi:...`` when the chain stays inside the provider's own
    hierarchy; ``PIV[<domain root>]:uuid:...`` when it crossed a bridge, so
    each cross-certified issuer is its own namespace.  Anchor rollover leaves
    the ID unchanged: the provider, not a particular root, is the scope.
    """
    scope = provider.name
    if identity.trust_domain:
        scope = f"{scope}[{identity.trust_domain}]"
    return f"{scope}:{provider.primary_id_selector(identity)}"


def parse_identity(
    cert: x509.Certificate,
    registry: ProviderRegistry | None = None,
    chain: list[x509.Certificate] | None = None,
) -> CertIdentity:
    """Parse an x509 certificate into a CertIdentity.

    ``primary_id`` is always scoped: ``<provider>:<identifier>`` for a matched
    provider, or ``dn:<issuer>;<subject>`` when no provider matched.  With
    *chain*, the identity also records its trust anchor and, if the chain
    crossed one of the provider's bridges, the trust domain -- which then
    becomes part of ``primary_id``.  Without *chain* (no chain validation),
    issuers sharing a provider cannot be told apart.

    Args:
        cert: The x509 client certificate.
        registry: Provider registry to match against. Defaults to
            an empty registry (credential_type will be UNKNOWN).
        chain: The validated chain, leaf first, as returned by
            ``verify_chain()``.
    """
    if registry is None:
        registry = ProviderRegistry()

    identity = CertIdentity()

    # Subject fields
    identity.cn = get_name_attr(cert.subject, NameOID.COMMON_NAME)
    identity.organization = get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    identity.ou = get_name_attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
    identity.subject_dn = cert.subject.rfc4514_string()
    identity.cert_issuer_dn = cert.issuer.rfc4514_string()

    # Certificate metadata
    identity.cert_serial = format(cert.serial_number, "x")
    identity.cert_not_after = cert.not_valid_after_utc.isoformat()

    # Email from SAN or subject
    identity.email = extract_email(cert)

    # Policy OIDs
    identity.policy_oids = get_policy_oids(cert)

    # Match provider by OID.  Fall back to subject heuristics only when no
    # provider claimed the OIDs at all: a certificate that disqualified every
    # claimant (a device asserting a person OID too) or matched ambiguously
    # stays UNKNOWN, whatever its subject says.  Never silently pick a provider.
    policy_set = set(identity.policy_oids)
    match = registry.resolve(policy_set)
    provider = match.provider
    if match.outcome is MatchOutcome.NO_MATCH:
        provider = registry.match_heuristic(
            identity.cn, identity.organization, identity.ou, policy_set
        )

    if provider:
        identity.credential_type = provider.name
        identity.intended_use = provider.intended_use
        provider.cn_parser(identity)
    else:
        identity.credential_type = "UNKNOWN"

    # Extract UUID and FASC-N from SAN (all types may have them)
    identity.piv_uuid = identity.piv_uuid or extract_san_uuid(cert)
    identity.fascn = identity.fascn or extract_san_fascn(cert)

    if chain:
        identity.trust_anchor = cert_fingerprint(chain[-1])
        if provider:
            identity.trust_domain = _trust_domain(chain, provider.bridge_ca_subjects)

    # Build stable primary key based on provider strategy
    if provider:
        identity.primary_id = _scoped_primary_id(provider, identity)
    else:
        identity.primary_id = scoped_dn(identity)

    return identity
