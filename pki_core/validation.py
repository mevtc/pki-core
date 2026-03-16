"""Certificate validation pipeline.

Composes identity extraction, validity period checking, and CRL revocation
into a single function call with configurable policy.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography import x509

from .certificate import CertificateError, is_expired, is_not_yet_valid
from .crl import CRLConfig, check_revocation
from .identity import CertIdentity, parse_identity
from .providers import ProviderRegistry

logger = logging.getLogger(__name__)


class ValidationStatus(StrEnum):
    """Outcome of certificate validation."""

    VALID = "valid"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ERROR = "error"


@dataclass
class CertificatePolicy:
    """Configuration controlling which checks validate_certificate performs."""

    check_validity_period: bool = True
    check_revocation: bool = True
    crl_config: CRLConfig = field(default_factory=CRLConfig)
    registry: ProviderRegistry | None = None
    issuer_certs: list[x509.Certificate] | None = None


@dataclass
class ValidationResult:
    """Result of certificate validation."""

    identity: CertIdentity | None = None
    status: ValidationStatus = ValidationStatus.VALID
    error: str | None = None


def validate_certificate(
    cert: x509.Certificate,
    policy: CertificatePolicy | None = None,
) -> ValidationResult:
    """Validate a certificate against the given policy.

    Performs in order:
    1. Identity extraction (parse_identity)
    2. Validity period check — not yet valid and expired (if policy.check_validity_period)
    3. CRL revocation check (if policy.check_revocation)

    Returns a ValidationResult with status and parsed identity.
    Short-circuits on first failure. Identity is populated even on failure
    (if identity extraction itself succeeded).
    """
    if policy is None:
        policy = CertificatePolicy()

    result = ValidationResult()

    # Step 1: Parse identity
    try:
        result.identity = parse_identity(cert, registry=policy.registry)
    except Exception as e:
        logger.error("Identity extraction failed: %s", e)
        result.status = ValidationStatus.ERROR
        result.error = f"Identity extraction failed: {e}"
        return result

    # Step 2: Check validity period
    if policy.check_validity_period:
        if is_not_yet_valid(cert):
            result.status = ValidationStatus.NOT_YET_VALID
            result.error = "Certificate is not yet valid"
            return result
        if is_expired(cert):
            result.status = ValidationStatus.EXPIRED
            result.error = "Certificate has expired"
            return result

    # Step 3: Check revocation
    if policy.check_revocation:
        try:
            check_revocation(cert, policy.crl_config, issuer_certs=policy.issuer_certs)
        except CertificateError as e:
            error_msg = str(e)
            if "revoked" in error_msg.lower():
                result.status = ValidationStatus.REVOKED
            else:
                result.status = ValidationStatus.ERROR
            result.error = error_msg
            return result

    return result
