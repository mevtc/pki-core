"""Certificate validation pipeline.

Composes chain verification, identity extraction, validity period checking,
and revocation into a single function call with configurable policy.

Configuration hierarchy::

    CertificatePolicy
    ├── check_chain, trust_store      (chain validation)
    ├── algorithm_policy              (AlgorithmPolicy, opt-in)
    ├── registry                      (identity extraction)
    └── revocation                    (RevocationPolicy, or None to skip)
        ├── checks                    (ordered RevocationCheck strategies)
        ├── issuer_certs              (CAs for CRL/OCSP verification)
        ├── strict                    (fail-closed vs fail-open)
        └── crl_config                (CRLConfig — cache mechanics)

Validation boundary
-------------------
pki-core handles:

- **RFC 5280 chain validation** via ``verify_chain()`` — signature verification,
  validity period of all certs in the chain, basic constraints, path length,
  key usage, and name constraints.
- **Identity extraction** — CN parsing, SAN fields (FASC-N, UUID, email),
  policy OID identification, and primary ID selection.
- **Validity period checks** — explicit ``is_expired`` / ``is_not_yet_valid``.
- **Revocation checking** — pluggable strategies via :class:`RevocationCheck`
  ABC.  Built-in: :data:`CRL` (HTTP fetch with stale-while-revalidate cache)
  and :data:`OCSP` (live query to OCSP responder from the AIA extension).
  Strategies are composed into an ordered sequence — the pipeline tries each
  in turn until one returns ``GOOD`` or ``REVOKED``.
- **Algorithm enforcement** — :class:`AlgorithmPolicy` validates public key
  type/size and signature hash algorithm.  Defaults match broadly accepted
  minimums; provider packs define standard-specific policies.

**Not covered by pki-core** (must be handled higher in the stack):

- **TLS challenge-response** — Proof that the client holds the private key
  matching the presented certificate.  This is performed by the TLS terminator
  (nginx ``ssl_verify_client``, AWS ALB mutual TLS, or similar).  FIPS 201-3
  Section 6.2.3.1 (PKI-AUTH) steps 3-6 are satisfied by the TLS handshake.
- **Certificate policy OID constraints during path building** —
  ``cryptography``'s path validator does not support the ``initial-policy-set``
  / ``policy-mapping`` inputs from RFC 5280 §6.1.1.  Applications should check
  policy OIDs after validation using ``get_policy_oids()`` and match against
  the expected set (e.g., ``id-fpki-common-authentication`` per FIPS 201-3
  Section 6.2.3.1 footnote 39).
- **Certificate Transparency** — SCT verification is not performed.
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography import x509
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

from .algorithms import AlgorithmPolicy, check_algorithms
from .certificate import CertificateError, is_expired, is_not_yet_valid
from .identity import CertIdentity, parse_identity
from .providers import ProviderRegistry
from .revocation import (
    RevocationPolicy,
    RevocationResult,
    run_revocation_checks,
)

logger = logging.getLogger(__name__)


class ValidationStatus(StrEnum):
    """Outcome of certificate validation."""

    VALID = "valid"
    CHAIN_UNTRUSTED = "chain_untrusted"
    ALGORITHM_NONCOMPLIANT = "algorithm_noncompliant"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    ERROR = "error"


@dataclass
class CertificatePolicy:
    """Configuration controlling which checks validate_certificate performs.

    Revocation checking is controlled by ``revocation`` — a
    :class:`~pki.core.revocation.RevocationPolicy` that groups strategy
    ordering, issuer certificates, CRL cache config, and strictness.
    Set to ``None`` to disable revocation checking entirely.

    Examples::

        from pki.core.revocation import CRL, OCSP, RevocationPolicy

        # CRL only (default)
        CertificatePolicy()

        # CRL first, OCSP fallback
        CertificatePolicy(revocation=RevocationPolicy(checks=(CRL, OCSP)))

        # No revocation checking
        CertificatePolicy(revocation=None)
    """

    check_chain: bool = False
    check_validity_period: bool = True
    algorithm_policy: AlgorithmPolicy | None = None
    revocation: RevocationPolicy | None = field(default_factory=RevocationPolicy)
    registry: ProviderRegistry | None = None
    trust_store: list[x509.Certificate] | None = None
    intermediates: list[x509.Certificate] | None = None


@dataclass
class ValidationResult:
    """Result of certificate validation."""

    identity: CertIdentity | None = None
    status: ValidationStatus = ValidationStatus.VALID
    error: str | None = None
    chain: list[x509.Certificate] | None = None


def verify_chain(
    cert: x509.Certificate,
    trust_store: list[x509.Certificate],
    intermediates: list[x509.Certificate] | None = None,
) -> list[x509.Certificate]:
    """Verify a certificate chain per RFC 5280.

    Uses ``cryptography``'s ``ClientVerifier`` which performs signature
    verification, validity period checking, basic constraints, key usage,
    and name constraints validation.

    Args:
        cert: The leaf (end-entity) certificate to verify.
        trust_store: Trusted root CA certificates.
        intermediates: Intermediate CA certificates (may be empty when the
            leaf is issued directly by a root).

    Returns:
        The validated certificate chain from leaf to root.

    Raises:
        CertificateError: If the chain cannot be validated or the trust
            store is empty.

    Note:
        This does **not** enforce certificate policy OID constraints.
        Use ``get_policy_oids()`` to check policy OIDs after chain
        validation.  See the module docstring for the full validation
        boundary.
    """
    if not trust_store:
        raise CertificateError("trust_store is empty; cannot verify chain")

    store = Store(trust_store)
    verifier = PolicyBuilder().store(store).build_client_verifier()
    try:
        result = verifier.verify(cert, intermediates or [])
        return list(result.chain)
    except VerificationError as e:
        raise CertificateError(f"Chain validation failed: {e}") from e


def validate_certificate(
    cert: x509.Certificate,
    policy: CertificatePolicy | None = None,
) -> ValidationResult:
    """Validate a certificate against the given policy.

    Performs in order:

    0. Chain validation — verify the cert chains to a trusted root
       (if ``policy.check_chain``)
    0b. Algorithm compliance — check key type/size and signature hash
        (if ``policy.algorithm_policy`` is set)
    1. Identity extraction (``parse_identity``)
    2. Validity period check — not yet valid / expired
       (if ``policy.check_validity_period``)
    3. Revocation check via ordered strategies
       (if ``policy.revocation`` is set)

    Returns a :class:`ValidationResult` with status and parsed identity.
    Short-circuits on first failure.  Identity is populated even on failure
    (if identity extraction itself succeeded).
    """
    if policy is None:
        policy = CertificatePolicy()

    result = ValidationResult()

    # Step 0: Chain validation
    if policy.check_chain:
        if policy.trust_store is None:
            result.status = ValidationStatus.ERROR
            result.error = "check_chain is enabled but no trust_store was provided"
            return result
        try:
            result.chain = verify_chain(cert, policy.trust_store, policy.intermediates)
        except CertificateError as e:
            # Still extract identity for logging before returning
            with contextlib.suppress(Exception):
                result.identity = parse_identity(cert, registry=policy.registry)
            result.status = ValidationStatus.CHAIN_UNTRUSTED
            result.error = str(e)
            return result

    # Step 0b: Algorithm compliance
    if policy.algorithm_policy is not None:
        passed, detail = check_algorithms(cert, policy.algorithm_policy)
        if not passed:
            # Still extract identity for logging
            with contextlib.suppress(Exception):
                result.identity = parse_identity(cert, registry=policy.registry)
            result.status = ValidationStatus.ALGORITHM_NONCOMPLIANT
            result.error = detail
            return result

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
    if policy.revocation is not None:
        rev_result, rev_detail = run_revocation_checks(policy.revocation, cert)
        if rev_result == RevocationResult.REVOKED:
            result.status = ValidationStatus.REVOKED
            result.error = rev_detail
            return result
        if rev_result == RevocationResult.UNAVAILABLE:
            result.status = ValidationStatus.ERROR
            result.error = rev_detail
            return result

    return result
