"""Certificate identity extraction.

Extracts structured identity information from x509 certificates using
a pluggable provider registry for CN parsing and primary ID selection.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509
from cryptography.x509.oid import NameOID

from .certificate import (
    extract_email,
    extract_san_fascn,
    extract_san_uuid,
    get_name_attr,
    get_policy_oids,
)
from .providers import ProviderRegistry


@dataclass
class CertIdentity:
    """Parsed identity from a client certificate."""

    primary_id: str | None = None
    credential_type: str | None = None
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

    def to_dict(self) -> dict:
        """Convert identity fields to a plain dictionary."""
        return {
            "primary_id": self.primary_id,
            "credential_type": self.credential_type,
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
        }


def parse_identity(
    cert: x509.Certificate,
    registry: ProviderRegistry | None = None,
) -> CertIdentity:
    """Parse an x509 certificate into a CertIdentity.

    Args:
        cert: The x509 client certificate.
        registry: Provider registry to match against. Defaults to
            an empty registry (credential_type will be UNKNOWN).
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

    # Match provider by OID, then heuristic fallback
    policy_set = set(identity.policy_oids)
    provider = registry.match_oids(policy_set)
    if provider is None:
        provider = registry.match_heuristic(identity.cn, identity.organization, identity.ou)
    if provider is None:
        all_providers = registry.all()
        provider = all_providers[-1] if all_providers else None

    if provider:
        identity.credential_type = provider.name
        provider.cn_parser(identity)
    else:
        identity.credential_type = "UNKNOWN"

    # Extract UUID and FASC-N from SAN (all types may have them)
    identity.piv_uuid = identity.piv_uuid or extract_san_uuid(cert)
    identity.fascn = identity.fascn or extract_san_fascn(cert)

    # Build stable primary key based on provider strategy
    if provider:
        identity.primary_id = provider.primary_id_selector(identity)
    else:
        identity.primary_id = f"dn:{identity.subject_dn}"

    return identity
