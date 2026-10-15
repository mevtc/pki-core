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
  key usage, name constraints, and Extended Key Usage.  The required EKU is
  configurable via ``expected_eku`` and defaults to ``id-kp-clientAuth``;
  set it to ``id-kp-emailProtection`` for S/MIME or ``None`` to skip the
  check.  A certificate carrying no EKU extension is unrestricted per
  RFC 5280 and satisfies any ``expected_eku``.
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
- **Trust anchors are self-signed roots only.**  ``verify_chain()`` moves
  any non-self-signed certificate in ``trust_store`` (DoD intermediates,
  Federal Bridge cross-certificates) to the intermediates pool, so it must
  chain to a root and its constraints apply.  A provider that declares
  ``trust_anchor_fingerprints`` additionally rejects chains ending at any
  other root.
- **Revocation covers the whole chain** when the chain was validated: every
  certificate except the root, each CRL verified against the issuer actually
  found in the chain.
- **Certificate policy OID constraints during path building** —
  ``cryptography``'s path validator does not support the ``initial-policy-set``
  / ``policy-mapping`` inputs from RFC 5280 §6.1.1.  Applications should check
  policy OIDs after validation using ``get_policy_oids()`` and match against
  the expected set (e.g., ``id-fpki-common-authentication`` per FIPS 201-3
  Section 6.2.3.1 footnote 39).  For the same reason the ``policyConstraints``
  and ``inhibitAnyPolicy`` extensions that Federal Bridge cross-certificates
  mark critical are *accepted but not processed*.
- **Certificate Transparency** — SCT verification is not performed.
"""

from __future__ import annotations

import contextlib
import dataclasses
import itertools
import logging
from dataclasses import dataclass, field
from enum import StrEnum

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)

from .algorithms import AlgorithmPolicy, check_algorithms
from .certificate import (
    CertificateError,
    cert_fingerprint,
    is_expired,
    is_not_yet_valid,
    is_self_signed,
)
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

        # S/MIME: encryption certificates assert emailProtection alone
        from cryptography.x509.oid import ExtendedKeyUsageOID

        CertificatePolicy(
            check_chain=True,
            trust_store=ca_certs,
            expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
        )
    """

    check_chain: bool = False
    check_validity_period: bool = True
    algorithm_policy: AlgorithmPolicy | None = None
    revocation: RevocationPolicy | None = field(default_factory=RevocationPolicy)
    registry: ProviderRegistry | None = None
    trust_store: list[x509.Certificate] | None = None
    intermediates: list[x509.Certificate] | None = None
    expected_eku: x509.ObjectIdentifier | None = ExtendedKeyUsageOID.CLIENT_AUTH


@dataclass
class ValidationResult:
    """Result of certificate validation."""

    identity: CertIdentity | None = None
    status: ValidationStatus = ValidationStatus.VALID
    error: str | None = None
    chain: list[x509.Certificate] | None = None


def _build_ee_extension_policy(
    expected_eku: x509.ObjectIdentifier | None,
) -> ExtensionPolicy:
    """Build an end-entity extension policy enforcing ``expected_eku``.

    Starts from ``webpki_defaults_ee()`` so every other end-entity extension
    check (key usage, basic constraints, SAN handling) is retained, and
    replaces only the Extended Key Usage rule.

    ``cryptography``'s ``ClientVerifier`` hard-codes an ``id-kp-clientAuth``
    requirement in its default end-entity extension policy.  That is correct
    for TLS client authentication and wrong for every other use of an X.509
    certificate -- notably S/MIME encryption certificates, which assert
    ``id-kp-emailProtection`` alone.

    Args:
        expected_eku: EKU OID the end-entity certificate must assert, or
            ``None`` to accept any EKU (the extension may still be present).

    Returns:
        An :class:`ExtensionPolicy` for end-entity certificates.
    """
    base = ExtensionPolicy.webpki_defaults_ee()

    if expected_eku is None:
        return base.may_be_present(x509.ExtendedKeyUsage, Criticality.AGNOSTIC, None)

    def _validate_eku(
        policy: object,
        cert: x509.Certificate,
        ext: x509.ExtendedKeyUsage | None,
    ) -> None:
        # An absent EKU is unrestricted per RFC 5280 -- only reject when the
        # extension is present and omits the required usage.
        if ext is not None and expected_eku not in ext:
            asserted = ", ".join(oid.dotted_string for oid in ext) or "none"
            raise ValueError(
                f"required EKU {expected_eku.dotted_string} not asserted "
                f"by end-entity certificate (asserts: {asserted})"
            )

    return base.may_be_present(x509.ExtendedKeyUsage, Criticality.AGNOSTIC, _validate_eku)


def _build_ca_extension_policy() -> ExtensionPolicy:
    """CA extension policy that admits Federal Bridge cross-certificates.

    ``webpki_defaults_ca()`` rejects any CA certificate carrying a critical
    extension it does not process.  FPKI cross-certificates mark
    ``policyConstraints`` and ``inhibitAnyPolicy`` critical, so without this
    every bridged path fails with "unaccounted-for critical extensions".
    ``cryptography`` implements no RFC 5280 policy processing, so these are
    accepted without being enforced -- the documented limitation, not a new
    one.  ``nameConstraints`` remains enforced.  ``policyMappings`` needs no
    entry: ``cryptography`` has no type for it and FPKI marks it non-critical.
    """
    return (
        ExtensionPolicy.webpki_defaults_ca()
        .may_be_present(x509.PolicyConstraints, Criticality.AGNOSTIC, None)
        .may_be_present(x509.InhibitAnyPolicy, Criticality.AGNOSTIC, None)
    )


def split_trust_anchors(
    certs: list[x509.Certificate],
) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Split CA certificates into ``(roots, intermediates)``.

    Only self-signed roots are trust anchors.  Everything else -- issuing
    CAs, bridge cross-certificates -- is an intermediate and must itself chain
    to a root.
    """
    roots: list[x509.Certificate] = []
    intermediates: list[x509.Certificate] = []
    for cert in certs:
        (roots if is_self_signed(cert) else intermediates).append(cert)
    return roots, intermediates


def verify_chain(
    cert: x509.Certificate,
    trust_store: list[x509.Certificate],
    intermediates: list[x509.Certificate] | None = None,
    expected_eku: x509.ObjectIdentifier | None = ExtendedKeyUsageOID.CLIENT_AUTH,
) -> list[x509.Certificate]:
    """Verify a certificate chain per RFC 5280.

    Uses ``cryptography``'s ``ClientVerifier`` which performs signature
    verification, validity period checking, basic constraints, key usage,
    and name constraints validation.

    Args:
        cert: The leaf (end-entity) certificate to verify.
        trust_store: Trusted CA certificates.  Only self-signed roots are
            used as anchors; any other certificate here is treated as an
            intermediate (see :func:`split_trust_anchors`).
        intermediates: Intermediate CA certificates (may be empty when the
            leaf is issued directly by a root).
        expected_eku: Extended Key Usage OID the end-entity certificate must
            assert if it carries an EKU extension.  Defaults to
            ``ExtendedKeyUsageOID.CLIENT_AUTH`` for TLS client authentication.
            Pass ``ExtendedKeyUsageOID.EMAIL_PROTECTION`` for S/MIME, or
            ``None`` to skip the EKU check entirely.

    Returns:
        The validated certificate chain from leaf to root.

    Raises:
        CertificateError: If the chain cannot be validated or the trust
            store is empty.

    Note:
        A certificate with **no** EKU extension is unrestricted per RFC 5280
        and passes any ``expected_eku``.  The check rejects only certificates
        that carry an EKU omitting the required usage.

    Note:
        This does **not** enforce certificate policy OID constraints.
        Use ``get_policy_oids()`` to check policy OIDs after chain
        validation.  See the module docstring for the full validation
        boundary.
    """
    roots, demoted = split_trust_anchors(trust_store)
    if not roots:
        raise CertificateError("trust_store contains no self-signed root; cannot verify chain")

    store = Store(roots)
    verifier = (
        PolicyBuilder()
        .store(store)
        .extension_policies(
            ca_policy=_build_ca_extension_policy(),
            ee_policy=_build_ee_extension_policy(expected_eku),
        )
        .build_client_verifier()
    )
    try:
        result = verifier.verify(cert, [*demoted, *(intermediates or [])])
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
            result.chain = verify_chain(
                cert,
                policy.trust_store,
                policy.intermediates,
                expected_eku=policy.expected_eku,
            )
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
        result.identity = parse_identity(cert, registry=policy.registry, chain=result.chain)
    except Exception as e:
        logger.error("Identity extraction failed: %s", e)
        result.status = ValidationStatus.ERROR
        result.error = f"Identity extraction failed: {e}"
        return result

    # Step 1b: The chain must end at a root authoritative for the provider
    anchor_error = _check_provider_anchor(result.identity, policy.registry, result.chain)
    if anchor_error:
        result.status = ValidationStatus.CHAIN_UNTRUSTED
        result.error = anchor_error
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

    # Step 3: Check revocation -- the leaf alone, or every non-root
    # certificate in a validated chain, each against its actual issuer.
    if policy.revocation is not None:
        for subject, rev_policy, target in _revocation_targets(
            policy.revocation, cert, result.chain
        ):
            rev_result, rev_detail = run_revocation_checks(rev_policy, target)
            if rev_result == RevocationResult.GOOD:
                continue
            if target is not cert:
                rev_detail = f"Chain certificate {subject}: {rev_detail}"
            result.status = (
                ValidationStatus.REVOKED
                if rev_result == RevocationResult.REVOKED
                else ValidationStatus.ERROR
            )
            result.error = rev_detail
            return result

    return result


def _check_provider_anchor(
    identity: CertIdentity,
    registry: ProviderRegistry | None,
    chain: list[x509.Certificate] | None,
) -> str | None:
    """Return an error if the chain's root is not pinned by the matched provider."""
    if not chain or registry is None or identity.credential_type is None:
        return None
    provider = registry.get(identity.credential_type)
    if provider is None or not provider.trust_anchor_fingerprints:
        return None
    if cert_fingerprint(chain[-1]) in provider.trust_anchor_fingerprints:
        return None
    return (
        f"Chain ends at {chain[-1].subject.rfc4514_string()}, which is not a trust "
        f"anchor for provider {provider.name!r}"
    )


def _revocation_targets(
    revocation: RevocationPolicy,
    cert: x509.Certificate,
    chain: list[x509.Certificate] | None,
) -> list[tuple[str, RevocationPolicy, x509.Certificate]]:
    """Certificates to revocation-check, each with the policy to check it under.

    Without a validated chain only the leaf is checked, under the caller's
    policy.  With one, every certificate but the root is checked, and its
    CRL/OCSP response is verified against the issuer the chain actually
    contains -- never against an unrelated CA with a matching name.
    """
    if not chain:
        return [(cert.subject.rfc4514_string(), revocation, cert)]
    return [
        (
            target.subject.rfc4514_string(),
            dataclasses.replace(revocation, issuer_certs=[issuer]),
            target,
        )
        for target, issuer in itertools.pairwise(chain)
    ]
