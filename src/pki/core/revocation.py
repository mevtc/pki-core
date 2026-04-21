"""Pluggable revocation checking strategies.

Provides a :class:`RevocationCheck` ABC that defines the interface for
certificate revocation checks, and two built-in implementations:

- :data:`CRL` — check via CRL distribution points with file-backed caching.
- :data:`OCSP` — check via OCSP responder URLs from the AIA extension.

Strategies are composed into an ordered sequence on
:class:`RevocationPolicy`.  The pipeline runner tries each strategy in
order: ``GOOD`` stops immediately, ``REVOKED`` stops and fails,
``UNAVAILABLE`` falls through to the next strategy.

Custom strategies can be created by subclassing :class:`RevocationCheck`::

    from pki.core.revocation import CRL, RevocationCheck, RevocationPolicy, RevocationResult

    class MyHSMCheck(RevocationCheck):
        def check(self, cert, policy):
            # query internal HSM revocation database
            ...
            return RevocationResult.GOOD, "HSM says OK"

    rev = RevocationPolicy(checks=(MyHSMCheck(), CRL))
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID

from .certificate import CertificateError
from .crl import CRLConfig
from .crl import check_revocation as _crl_check_revocation

logger = logging.getLogger(__name__)


class RevocationResult(StrEnum):
    """Outcome of a single revocation check."""

    GOOD = "good"
    REVOKED = "revoked"
    UNAVAILABLE = "unavailable"


class RevocationCheck(ABC):
    """Abstract base class for revocation checking strategies.

    Subclass this and implement :meth:`check` to create a custom
    revocation checking strategy.
    """

    @abstractmethod
    def check(
        self,
        cert: x509.Certificate,
        policy: RevocationPolicy,
    ) -> tuple[RevocationResult, str]:
        """Check whether *cert* has been revoked.

        Args:
            cert: The certificate to check.
            policy: Revocation policy containing issuer certificates,
                CRL cache config, and strictness settings.

        Returns:
            A ``(result, detail)`` tuple where *result* is a
            :class:`RevocationResult` and *detail* is a human-readable
            message suitable for logging.
        """
        ...


class CRLCheck(RevocationCheck):
    """Check revocation via CRL distribution points.

    Delegates to :func:`pki.core.crl.check_revocation` which uses a
    stale-while-revalidate file-backed cache.
    """

    def check(
        self,
        cert: x509.Certificate,
        policy: RevocationPolicy,
    ) -> tuple[RevocationResult, str]:
        """Perform a CRL-based revocation check against distribution points."""
        try:
            _crl_check_revocation(cert, policy.crl_config, issuer_certs=policy.issuer_certs)
            return RevocationResult.GOOD, "CRL check passed"
        except CertificateError as e:
            msg = str(e)
            if "revoked" in msg.lower():
                return RevocationResult.REVOKED, msg
            # CRL unavailable or verification failure — let next strategy try
            logger.debug("CRL check unavailable: %s", msg)
            return RevocationResult.UNAVAILABLE, msg

    def __repr__(self) -> str:
        """Return string representation of the CRL check strategy."""
        return "CRL"


class OCSPCheck(RevocationCheck):
    """Check revocation via OCSP responder from the AIA extension.

    Requires at least one issuer certificate to build the OCSP request.
    """

    def check(
        self,
        cert: x509.Certificate,
        policy: RevocationPolicy,
    ) -> tuple[RevocationResult, str]:
        """Perform an OCSP-based revocation check via AIA responder URLs."""
        urls = _get_ocsp_responder_urls(cert)
        if not urls:
            return RevocationResult.UNAVAILABLE, "No OCSP responder URL in AIA extension"

        if not policy.issuer_certs:
            return RevocationResult.UNAVAILABLE, "No issuer certificates for OCSP request"

        issuer = _find_issuer(cert, policy.issuer_certs)
        if issuer is None:
            return (
                RevocationResult.UNAVAILABLE,
                f"No issuer certificate matches cert issuer: {cert.issuer.rfc4514_string()}",
            )

        timeout = policy.crl_config.fetch_timeout
        for url in urls:
            result, detail = _query_ocsp(cert, issuer, url, timeout)
            if result != RevocationResult.UNAVAILABLE:
                return result, detail

        return RevocationResult.UNAVAILABLE, f"All OCSP responders unavailable ({len(urls)} tried)"

    def __repr__(self) -> str:
        """Return string representation of the OCSP check strategy."""
        return "OCSP"


# Module-level singletons
CRL = CRLCheck()
OCSP = OCSPCheck()

# Default checks when none are specified
_DEFAULT_CHECKS: tuple[RevocationCheck, ...] = (CRL,)


@dataclass
class RevocationPolicy:
    """Revocation checking configuration.

    Groups all revocation-related settings — strategy ordering, issuer
    certificates, cache config, and strictness — into a single object.

    Attributes:
        checks: Ordered sequence of :class:`RevocationCheck` strategies.
            The pipeline tries each in order; ``GOOD`` or ``REVOKED``
            stops immediately, ``UNAVAILABLE`` falls through.
        issuer_certs: CA certificates used for CRL signature verification
            and OCSP request building.  Required for signature verification;
            ``None`` skips CRL signature checks.
        crl_config: Cache and fetch configuration for CRL checks.
        strict: If ``True`` (default), return ``UNAVAILABLE`` when all
            checks fail (fail-closed).  If ``False``, return ``GOOD``
            with a warning (fail-open).

    Examples::

        from pki.core.revocation import CRL, OCSP, RevocationPolicy

        # CRL only (default)
        RevocationPolicy()

        # CRL first, OCSP fallback
        RevocationPolicy(checks=(CRL, OCSP))

        # OCSP only, non-strict
        RevocationPolicy(checks=(OCSP,), strict=False)
    """

    checks: Sequence[RevocationCheck] = _DEFAULT_CHECKS
    issuer_certs: list[x509.Certificate] | None = None
    crl_config: CRLConfig = field(default_factory=CRLConfig)
    strict: bool = True


def run_revocation_checks(
    policy: RevocationPolicy,
    cert: x509.Certificate,
) -> tuple[RevocationResult, str]:
    """Run an ordered sequence of revocation checks.

    Tries each check in order:

    - ``GOOD`` — stops, returns immediately.
    - ``REVOKED`` — stops, returns immediately.
    - ``UNAVAILABLE`` — logs and tries the next check.

    If all checks return ``UNAVAILABLE``, behaviour depends on
    ``policy.strict``: ``True`` returns ``UNAVAILABLE`` (fail-closed),
    ``False`` returns ``GOOD`` (fail-open with warning).
    """
    last_detail = "No revocation checks configured"

    for check in policy.checks:
        result, detail = check.check(cert, policy)
        logger.debug("Revocation check %r: %s — %s", check, result, detail)

        if result == RevocationResult.GOOD:
            return result, detail
        if result == RevocationResult.REVOKED:
            return result, detail

        last_detail = detail

    # All checks returned UNAVAILABLE
    if policy.strict:
        return (
            RevocationResult.UNAVAILABLE,
            f"All revocation checks unavailable (strict mode): {last_detail}",
        )
    logger.warning("All revocation checks unavailable (non-strict) — allowing: %s", last_detail)
    return RevocationResult.GOOD, f"All checks unavailable (non-strict): {last_detail}"


# ---------------------------------------------------------------------------
# OCSP helpers
# ---------------------------------------------------------------------------


def _get_ocsp_responder_urls(cert: x509.Certificate) -> list[str]:
    """Extract OCSP responder HTTP(S) URLs from the AIA extension."""
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
    except x509.ExtensionNotFound:
        return []

    urls = []
    for desc in aia.value:  # type: ignore[attr-defined]
        if desc.access_method == AuthorityInformationAccessOID.OCSP and isinstance(
            desc.access_location, x509.UniformResourceIdentifier
        ):
            url = desc.access_location.value
            if url.startswith(("http://", "https://")):
                urls.append(url)
    return urls


def _find_issuer(
    cert: x509.Certificate,
    issuer_certs: list[x509.Certificate],
) -> x509.Certificate | None:
    """Find the issuer certificate for *cert* by matching issuer DN."""
    for ca in issuer_certs:
        if ca.subject == cert.issuer:
            return ca
    return None


def _query_ocsp(
    cert: x509.Certificate,
    issuer: x509.Certificate,
    url: str,
    timeout: int,
) -> tuple[RevocationResult, str]:
    """Send an OCSP request and interpret the response."""
    try:
        builder = ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(cert, issuer, hashes.SHA256())
        ocsp_request = builder.build()
        request_data = ocsp_request.public_bytes(serialization.Encoding.DER)
    except Exception as e:
        return RevocationResult.UNAVAILABLE, f"Failed to build OCSP request: {e}"

    try:
        resp = httpx.post(
            url,
            content=request_data,
            headers={"Content-Type": "application/ocsp-request"},
            timeout=timeout,
        )
        resp.raise_for_status()
    except Exception as e:
        logger.debug("OCSP request to %s failed: %s", url, e)
        return RevocationResult.UNAVAILABLE, f"OCSP request failed ({url}): {e}"

    try:
        ocsp_response = ocsp.load_der_ocsp_response(resp.content)
    except Exception as e:
        return RevocationResult.UNAVAILABLE, f"Failed to parse OCSP response from {url}: {e}"

    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        return (
            RevocationResult.UNAVAILABLE,
            f"OCSP responder returned status {ocsp_response.response_status.name} ({url})",
        )

    # Verify the OCSP response signature per RFC 6960 Section 3.2.
    try:
        _verify_ocsp_response_signature(ocsp_response, issuer)
    except Exception as e:
        logger.debug("OCSP response signature verification failed (%s): %s", url, e)
        return RevocationResult.UNAVAILABLE, f"OCSP response signature invalid ({url}): {e}"

    cert_status = ocsp_response.certificate_status
    if cert_status == ocsp.OCSPCertStatus.GOOD:
        return RevocationResult.GOOD, f"OCSP: certificate is good ({url})"
    if cert_status == ocsp.OCSPCertStatus.REVOKED:
        return RevocationResult.REVOKED, f"OCSP: certificate is revoked ({url})"

    # UNKNOWN
    return RevocationResult.UNAVAILABLE, f"OCSP: certificate status unknown ({url})"


def _verify_ocsp_response_signature(
    ocsp_response: ocsp.OCSPResponse,
    issuer: x509.Certificate,
) -> None:
    """Verify an OCSP response signature per RFC 6960 Section 3.2.

    The response must be signed by either the issuer CA itself or by a
    certificate issued by that CA with the id-kp-OCSPSigning EKU.

    Raises ``CertificateError`` if the signature cannot be verified.
    """
    from cryptography.x509.oid import ExtendedKeyUsageOID

    # Determine the responder's signing certificate.
    responder_certs = ocsp_response.certificates
    if responder_certs:
        # Delegated responder — verify it was issued by the CA and has
        # the id-kp-OCSPSigning EKU.
        responder_cert = responder_certs[0]
        try:
            eku = responder_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            if ExtendedKeyUsageOID.OCSP_SIGNING not in eku.value:
                raise CertificateError("OCSP responder certificate lacks id-kp-OCSPSigning EKU")
        except x509.ExtensionNotFound as e:
            raise CertificateError("OCSP responder certificate has no EKU extension") from e
        # Verify the responder cert was issued by the CA.
        if responder_cert.issuer != issuer.subject:
            raise CertificateError("OCSP responder certificate was not issued by the expected CA")
        try:
            _verify_signature(
                issuer.public_key(),
                responder_cert.signature,
                responder_cert.tbs_certificate_bytes,
                responder_cert.signature_hash_algorithm,
            )
        except Exception as e:
            raise CertificateError(f"OCSP responder certificate signature invalid: {e}") from e
        signing_key = responder_cert.public_key()
    else:
        # Response signed directly by the issuer CA.
        signing_key = issuer.public_key()

    # Verify the OCSP response signature itself.
    try:
        _verify_signature(
            signing_key,
            ocsp_response.signature,
            ocsp_response.tbs_response_bytes,
            ocsp_response.signature_hash_algorithm,
        )
    except Exception as e:
        raise CertificateError(f"OCSP response signature verification failed: {e}") from e


def _verify_signature(
    public_key, signature: bytes, data: bytes, hash_algorithm: hashes.HashAlgorithm | None
) -> None:
    """Verify a signature using the correct algorithm for the key type."""
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if hash_algorithm is None:
        hash_algorithm = hashes.SHA256()

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
    else:
        raise CertificateError(f"Unsupported OCSP responder key type: {type(public_key).__name__}")
