"""CRL fetching and revocation checking with stale-while-revalidate caching."""

import hashlib
import logging
import os
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from cryptography import x509
from platformdirs import user_cache_dir

from .certificate import CertificateError

logger = logging.getLogger(__name__)


class CRLRefreshError(CertificateError):
    """Raised when a background CRL refresh fails."""


@dataclass
class CRLConfig:
    """Configuration for CRL cache behaviour.

    ``cache_dir`` defaults to the platform-standard user cache location
    based on ``app_name`` (e.g. ``~/.cache/pki-core/crls`` on Linux).
    Pass an explicit ``cache_dir`` to override.

    Attributes:
        app_name: Application name for default cache directory.
        cache_dir: Explicit cache directory (overrides app_name default).
        cache_ttl: Seconds before a cached CRL is considered stale and
            triggers a background refresh.  The stale copy is still served
            while refreshing.
        strict: If True (default), raise ``CertificateError`` when a CRL
            cannot be fetched or verified.  If False, log a warning and
            allow the request.
        fetch_timeout: HTTP fetch timeout in seconds.
        max_crl_bytes: Maximum CRL response size in bytes.  Responses
            larger than this are rejected.  Default is 10 MB; DoD CRLs
            may require a higher limit.
        max_acceptable_age: Maximum age in seconds of a cached CRL before
            it is considered too old to trust, even as a stale fallback.
            If a cached CRL exceeds this age and cannot be refreshed,
            the check fails (in strict mode) rather than serving an
            unacceptably stale copy.  Default is 0 (disabled — any cached
            CRL is acceptable as a stale fallback).
    """

    app_name: str = "pki-core"
    cache_dir: str = ""
    cache_ttl: int = 3600  # seconds
    strict: bool = True
    fetch_timeout: int = 10  # seconds
    max_crl_bytes: int = 10 * 1024 * 1024  # 10 MB
    max_acceptable_age: int = 0  # 0 = disabled

    def __post_init__(self):
        """Apply defaults and validate configuration constraints."""
        if not self.cache_dir:
            self.cache_dir = str(Path(user_cache_dir(self.app_name)) / "crls")


def get_crl_distribution_points(cert: x509.Certificate) -> list[str]:
    """Extract HTTP(S) CRL distribution point URLs from a certificate."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
    except x509.ExtensionNotFound:
        return []

    urls = []
    for dp in ext.value:
        if dp.full_name is None:
            continue
        for name in dp.full_name:
            if isinstance(name, x509.UniformResourceIdentifier):
                url = name.value
                if url.startswith("http://") or url.startswith("https://"):
                    urls.append(url)
    return urls


def verify_crl(
    crl: x509.CertificateRevocationList,
    issuer_certs: list[x509.Certificate],
    strict: bool = True,
) -> bool:
    """Verify a CRL's signature and freshness against a set of CA certificates.

    Checks that:
    1. A CA certificate whose subject matches the CRL issuer is present.
    2. The CRL signature is valid for that CA's public key.
    3. The CRL's ``nextUpdate`` has not passed (stale CRL protection).

    Returns True if the CRL is valid.  In strict mode, raises
    ``CertificateError`` on any failure.  In non-strict mode, logs a warning
    and returns False.
    """
    crl_issuer_dn = crl.issuer

    # Find matching issuer cert by parsed DN comparison (handles attribute
    # ordering and encoding differences that string comparison would miss).
    issuer_cert = None
    for ca in issuer_certs:
        if ca.subject == crl_issuer_dn:
            issuer_cert = ca
            break

    if issuer_cert is None:
        msg = f"No CA certificate found for CRL issuer: {crl_issuer_dn.rfc4514_string()}"
        if strict:
            raise CertificateError(msg)
        logger.warning(msg)
        return False

    # Verify signature.
    if not crl.is_signature_valid(issuer_cert.public_key()):  # type: ignore[arg-type]
        msg = f"CRL signature verification failed for issuer: {crl_issuer_dn.rfc4514_string()}"
        if strict:
            raise CertificateError(msg)
        logger.warning(msg)
        return False

    # Verify nextUpdate hasn't passed.
    if crl.next_update_utc and crl.next_update_utc < datetime.now(UTC):
        msg = f"CRL has expired (nextUpdate={crl.next_update_utc.isoformat()})"
        if strict:
            raise CertificateError(msg)
        logger.warning(msg)
        return False

    logger.debug("CRL signature valid, issuer=%s", crl_issuer_dn.rfc4514_string())
    return True


def load_ca_certs_from_pem(pem_data: str | bytes) -> list[x509.Certificate]:
    """Parse all certificates from a PEM bundle.

    Useful for loading a CA bundle file into a list suitable for passing
    as ``issuer_certs`` to :func:`check_revocation` or :func:`verify_crl`.
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode()
    return x509.load_pem_x509_certificates(pem_data)


def check_revocation(
    cert: x509.Certificate,
    config: CRLConfig,
    issuer_certs: list[x509.Certificate] | None = None,
) -> None:
    """Check certificate revocation against CRL distribution points.

    Uses a stale-while-revalidate cache strategy:
    - Fresh cache  -> used immediately, no network I/O.
    - Stale cache  -> used immediately; background thread refreshes it.
    - No cache     -> blocking fetch (first-ever request only).

    Raises CertificateError if the certificate's serial number appears in any CRL.
    If a CRL cannot be fetched and no cached copy exists, behaviour is controlled
    by config.strict (default True -> raise).

    If ``issuer_certs`` is provided, each CRL's signature and freshness are
    verified against the CA certificates before the revocation check.  Without
    ``issuer_certs``, signature verification is skipped (backward compatible).
    """
    urls = get_crl_distribution_points(cert)
    if not urls:
        logger.warning(
            "Certificate serial=%s has no CRL distribution points; skipping revocation check",
            format(cert.serial_number, "x"),
        )
        return

    for url in urls:
        try:
            crl = get_crl(url, config)
        except CertificateError:
            raise
        except Exception as e:
            logger.error("CRL unavailable for %s: %s", url, e)
            if config.strict:
                raise CertificateError("Could not verify revocation status; CRL unavailable") from e
            logger.warning("strict=false -- allowing without revocation check for %s", url)
            continue

        # Verify CRL signature if CA certs are available.
        if issuer_certs is not None:
            verify_crl(crl, issuer_certs, strict=config.strict)
        else:
            logger.debug(
                "No issuer_certs provided; skipping CRL signature verification for %s", url
            )

        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            raise CertificateError(
                f"Certificate has been revoked (serial {format(cert.serial_number, 'x')})"
            )


def get_crl(url: str, config: CRLConfig) -> x509.CertificateRevocationList:
    """Return a parsed CRL for the given URL using a file-backed cache.

    Strategy (stale-while-revalidate):
      1. Fresh cache  -> return immediately.
      2. Stale cache  -> return stale copy; spawn background thread to refresh.
      3. No cache     -> fetch synchronously, cache result, return.
    """
    cache_dir = Path(config.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
    cache_file = cache_dir / f"{url_hash}.crl"

    try:
        st = cache_file.stat()
        age = time.time() - st.st_mtime
        data = cache_file.read_bytes()
    except FileNotFoundError:
        data = None
        age = float("inf")

    if data is not None:
        if age < config.cache_ttl:
            return parse_crl_bytes(data)

        # Cache is stale — check if it's too old to serve even as a fallback
        if config.max_acceptable_age and age > config.max_acceptable_age:
            logger.warning(
                "CRL cache for %s is %.0fs old (max_acceptable_age=%d) -- forcing refresh",
                url,
                age,
                config.max_acceptable_age,
            )
            return refresh_crl(url, cache_file, config)

        logger.debug(
            "CRL stale (%.0fs old) for %s -- serving cache, refreshing in background",
            age,
            url,
        )
        threading.Thread(
            target=_refresh_crl_background,
            args=(url, cache_file, config),
            daemon=True,
        ).start()
        return parse_crl_bytes(data)

    logger.debug("No CRL cache for %s -- fetching synchronously", url)
    return refresh_crl(url, cache_file, config)


def _refresh_crl_background(url: str, cache_file: Path, config: CRLConfig) -> None:
    """Wrapper for background CRL refresh that logs exceptions.

    Raises CRLRefreshError so that callers using a custom thread pool or
    callback mechanism can observe the failure. In the default daemon-thread
    usage, the exception is logged and then discarded.
    """
    try:
        refresh_crl(url, cache_file, config)
    except Exception as e:
        logger.error("Background CRL refresh failed for %s: %s", url, e)
        raise CRLRefreshError(f"Background CRL refresh failed for {url}: {e}") from e


def refresh_crl(
    url: str, cache_file: Path, config: CRLConfig | None = None
) -> x509.CertificateRevocationList:
    """Fetch a CRL from url, write it to cache_file, and return parsed CRL.

    Called directly (blocking) when no cache exists, or from ``_refresh_crl_background``
    when the cache is stale.  Raises ``ValueError`` if the response exceeds
    ``config.max_crl_bytes``.
    """
    if config is None:
        config = CRLConfig()
    try:
        resp = httpx.get(url, timeout=config.fetch_timeout, follow_redirects=True)
        resp.raise_for_status()
        data = resp.content
        if len(data) > config.max_crl_bytes:
            raise ValueError(
                f"CRL from {url} exceeds size limit ({len(data)} > {config.max_crl_bytes} bytes)"
            )
        crl = parse_crl_bytes(data)
        tmp = cache_file.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        tmp.rename(cache_file)
        logger.debug("CRL cached from %s (%d bytes)", url, len(data))
        return crl
    except CertificateError:
        raise
    except Exception as e:
        logger.error("Failed to fetch/cache CRL from %s: %s", url, e)
        raise


def parse_crl_bytes(data: bytes) -> x509.CertificateRevocationList:
    """Load a CRL from DER bytes (common format) with PEM fallback."""
    try:
        return x509.load_der_x509_crl(data)
    except Exception:
        pass
    try:
        return x509.load_pem_x509_crl(data)
    except Exception as e:
        raise CertificateError(f"Failed to parse CRL: {e}") from e


def prefetch_crls(cert: x509.Certificate, config: CRLConfig) -> dict[str, str]:
    """Proactively fetch and cache CRLs for a certificate.

    Intended for scheduled invocation (cron / Lambda) to keep the CRL cache
    warm so that real requests never block on a network fetch.

    Returns a dict mapping each CRL URL to "refreshed", "skipped (fresh)",
    or "error: <message>".
    """
    urls = get_crl_distribution_points(cert)
    if not urls:
        return {}

    cache_dir = Path(config.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, str] = {}

    for url in urls:
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = cache_dir / f"{url_hash}.crl"
        if cache_file.exists():
            age = time.time() - cache_file.stat().st_mtime
            if age < config.cache_ttl:
                results[url] = "skipped (fresh)"
                continue
        try:
            refresh_crl(url, cache_file, config)
            results[url] = "refreshed"
        except Exception as e:
            results[url] = f"error: {e}"

    return results


def get_crl_max_age(cert: x509.Certificate, config: CRLConfig) -> float | None:
    """Return the age in seconds of the oldest cached CRL for a certificate.

    Returns None if no CRL distribution points are found.
    Returns float("inf") if any CRL has no cached file yet.
    """
    urls = get_crl_distribution_points(cert)
    if not urls:
        return None

    cache_dir = Path(config.cache_dir)
    max_age: float | None = None

    for url in urls:
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:24]
        cache_file = cache_dir / f"{url_hash}.crl"
        if not cache_file.exists():
            return float("inf")
        age = time.time() - cache_file.stat().st_mtime
        if max_age is None or age > max_age:
            max_age = age

    return max_age
