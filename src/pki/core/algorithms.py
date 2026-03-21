"""Cryptographic algorithm policy enforcement.

Validates that a certificate's public key and signature algorithm meet
minimum requirements.  pki-core provides a generic :class:`AlgorithmPolicy`
dataclass whose defaults match broadly accepted minimums (RSA 2048+,
ECC P-256/P-384, SHA-256+).  Provider packs such as ``pki-federal`` define
their own policy constants aligned with specific standards (e.g., SP 800-78).

Example::

    from pki.core.algorithms import AlgorithmPolicy, check_algorithms

    # Use defaults (RSA 2048+, P-256/P-384, SHA-256+)
    result, detail = check_algorithms(cert, AlgorithmPolicy())

    # ECC P-384 only, no RSA
    strict = AlgorithmPolicy(
        min_rsa_bits=0,
        allowed_curves=frozenset({"secp384r1"}),
    )
    result, detail = check_algorithms(cert, strict)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

logger = logging.getLogger(__name__)

# Defaults that match broadly accepted minimums.
_DEFAULT_CURVES = frozenset({"secp256r1", "secp384r1"})
_DEFAULT_HASHES = frozenset({"sha256", "sha384", "sha512"})


@dataclass(frozen=True)
class AlgorithmPolicy:
    """Approved cryptographic algorithms for certificate validation.

    Defaults are broadly accepted minimums.  Provider packs (e.g.,
    ``pki-federal``) should define constants with values aligned to their
    governing standard.

    Attributes:
        min_rsa_bits: Minimum RSA key size in bits.  Set to ``0`` to
            disallow RSA entirely.
        allowed_curves: Frozenset of allowed elliptic curve names
            (lowercase, as returned by ``key.curve.name``).
        allowed_hashes: Frozenset of allowed signature hash algorithm
            names (lowercase, as returned by
            ``cert.signature_hash_algorithm.name``).
    """

    min_rsa_bits: int = 2048
    allowed_curves: frozenset[str] = field(default_factory=lambda: _DEFAULT_CURVES)
    allowed_hashes: frozenset[str] = field(default_factory=lambda: _DEFAULT_HASHES)


def check_algorithms(
    cert: x509.Certificate,
    policy: AlgorithmPolicy,
) -> tuple[bool, str]:
    """Check that a certificate's algorithms comply with *policy*.

    Validates:

    1. **Public key type and size** — RSA keys must be at least
       ``policy.min_rsa_bits``.  EC keys must use a curve in
       ``policy.allowed_curves``.  Other key types (DSA, Ed25519, etc.)
       are rejected.
    2. **Signature hash algorithm** — must be in ``policy.allowed_hashes``.

    Args:
        cert: The certificate to check.
        policy: Algorithm requirements.

    Returns:
        A ``(passed, detail)`` tuple.  *passed* is ``True`` if the
        certificate meets all requirements, ``False`` otherwise.
        *detail* is a human-readable message.
    """
    public_key = cert.public_key()

    # Check public key type and size
    if isinstance(public_key, rsa.RSAPublicKey):
        if policy.min_rsa_bits == 0:
            return False, "RSA keys are not allowed by algorithm policy"
        key_size = public_key.key_size
        if key_size < policy.min_rsa_bits:
            return (
                False,
                f"RSA key size {key_size} bits is below minimum {policy.min_rsa_bits}",
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name.lower()
        if curve_name not in policy.allowed_curves:
            return (
                False,
                f"EC curve {public_key.curve.name} is not in allowed set "
                f"{sorted(policy.allowed_curves)}",
            )
    else:
        key_type = type(public_key).__name__
        return False, f"Unsupported public key type: {key_type}"

    # Check signature hash algorithm
    hash_alg = cert.signature_hash_algorithm
    if hash_alg is None:
        # EdDSA and other algorithms don't have a separate hash
        return False, "Certificate has no signature hash algorithm (unsupported signature type)"

    hash_name = hash_alg.name.lower()
    if hash_name not in policy.allowed_hashes:
        return (
            False,
            f"Signature hash algorithm {hash_alg.name} is not in allowed set "
            f"{sorted(policy.allowed_hashes)}",
        )

    return True, "Algorithm check passed"
