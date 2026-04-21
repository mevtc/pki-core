"""CA trust store management.

Downloads, parses, deduplicates, and merges CA certificate bundles
from provider-defined trust store sources.
"""

import io
import logging
import zipfile
from pathlib import Path

import httpx
from cryptography.hazmat.primitives.serialization.pkcs7 import (
    load_der_pkcs7_certificates,
    load_pem_pkcs7_certificates,
)
from cryptography.x509 import load_der_x509_certificate

from .certificate import cert_fingerprint, cert_to_pem
from .providers import ProviderRegistry

logger = logging.getLogger(__name__)

try:
    from importlib.metadata import version as _pkg_version

    USER_AGENT = f"pki-core/{_pkg_version('pki-core')}"
except Exception:
    USER_AGENT = "pki-core"

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


def download(url: str, timeout: int = 60, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Download a URL and return raw bytes.

    Raises ``ValueError`` if the response exceeds *max_bytes*.
    """
    logger.info("Downloading %s", url)
    resp = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    )
    resp.raise_for_status()
    if len(resp.content) > max_bytes:
        raise ValueError(
            f"Download from {url} exceeds size limit ({len(resp.content)} > {max_bytes} bytes)"
        )
    logger.info("Downloaded %d bytes from %s", len(resp.content), url)
    return resp.content


def fetch_trust_store_source(source) -> list:
    """Download and parse certificates from a single TrustStoreSource.

    Dispatches on source.format: pkcs7_zip, pkcs7_der, der.
    """
    fmt = source.format
    if fmt == "pkcs7_zip":
        return _fetch_pkcs7_zip(source.url)
    elif fmt == "pkcs7_der":
        return _fetch_pkcs7_der(source.url)
    elif fmt == "der":
        return _fetch_der_cert(source.url)
    else:
        logger.warning("Unknown trust store format: %s", fmt)
        return []


def _fetch_pkcs7_zip(url: str) -> list:
    """Download ZIP containing PKCS7 bundles, parse all certs."""
    certs = []
    zip_data = download(url)
    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        for name in zf.namelist():
            if not (name.endswith(".p7b") or name.endswith(".p7c")):
                continue
            if ".." in name or name.startswith("/"):
                logger.warning("Skipping suspicious ZIP entry: %s", name)
                continue
            # Guard against zip path traversal — ensure the resolved path
            # stays within the current working directory.
            target = Path(name).resolve()
            cwd = Path.cwd().resolve()
            if not str(target).startswith(str(cwd)):
                logger.warning("Skipping zip entry with path traversal: %s", name)
                continue
            p7_data = zf.read(name)
            try:
                parsed = load_pem_pkcs7_certificates(p7_data)
                certs.extend(parsed)
            except Exception:
                try:
                    parsed = load_der_pkcs7_certificates(p7_data)
                    certs.extend(parsed)
                except Exception as e:
                    logger.warning("Could not parse %s: %s", name, e)
    return certs


def _fetch_pkcs7_der(url: str) -> list:
    """Download a DER-encoded PKCS7 bundle."""
    data = download(url)
    return list(load_der_pkcs7_certificates(data))


def _fetch_der_cert(url: str) -> list:
    """Download a single DER-encoded X.509 certificate."""
    data = download(url)
    return [load_der_x509_certificate(data)]


def merge_and_deduplicate(
    cert_lists: list[tuple[str, list]],
    filter_fn=None,
) -> tuple[str, dict]:
    """Merge certificate lists, deduplicate by fingerprint, return PEM bundle.

    Args:
        cert_lists: List of (source_label, cert_list) tuples.
        filter_fn: Optional callable(cert) -> bool. If provided, only certs
            where filter_fn returns True are included.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    seen: dict[str, str] = {}
    pem_parts = []

    for source, certs in cert_lists:
        for cert in certs:
            fp = cert_fingerprint(cert)
            if fp in seen:
                continue
            if filter_fn and not filter_fn(cert):
                logger.debug("Skipping filtered cert: %s", cert.subject)
                continue
            seen[fp] = source
            pem_parts.append(cert_to_pem(cert))

    sources = set(seen.values())
    stats = {src: sum(1 for s in seen.values() if s == src) for src in sources}
    stats["total"] = len(seen)

    logger.info("Merged bundle: %s = %d unique certificates", stats, stats["total"])
    return "".join(pem_parts), stats


def build_bundle_for_provider(
    provider,
    output_path: str | None = None,
    filter_fn=None,
) -> tuple[str, dict]:
    """Fetch CA certificates for a single provider and build a PEM bundle.

    Use this when you need per-provider bundles (e.g., a milter that verifies
    against multiple PKIs and needs to know which one matched).

    Args:
        provider: An AuthProvider with trust_store_sources defined.
        output_path: If provided, write the PEM bundle to this path.
        filter_fn: Optional callable(cert) -> bool for filtering.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    cert_lists = []
    for source in provider.trust_store_sources:
        label = source.label or provider.name
        try:
            certs = fetch_trust_store_source(source)
            logger.info("Fetched %d certs from %s (%s)", len(certs), source.url, label)
            cert_lists.append((label, certs))
        except Exception as e:
            logger.error("Failed to fetch %s: %s", source.url, e)

    if not cert_lists or not any(certs for _, certs in cert_lists):
        raise RuntimeError(f"No certificates fetched from provider {provider.name!r}")

    pem_bundle, stats = merge_and_deduplicate(cert_lists, filter_fn=filter_fn)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem_bundle)
        logger.info("Provider bundle written to %s (%s)", output_path, provider.name)

    return pem_bundle, stats


def build_ca_bundle_for_providers(
    registry: ProviderRegistry,
    output_path: str | None = None,
    filter_fn=None,
) -> tuple[str, dict]:
    """Fetch CA certificates for all providers in a registry.

    Only loads CAs from enabled providers, enforcing least-privilege on the
    trust chain.

    Args:
        registry: ProviderRegistry (required).
        output_path: If provided, write the PEM bundle to this path.
        filter_fn: Optional callable(cert) -> bool for filtering.

    Returns:
        Tuple of (pem_bundle_string, stats_dict).
    """
    cert_lists = []
    for provider in registry.all():
        for source in provider.trust_store_sources:
            label = source.label or provider.name
            try:
                certs = fetch_trust_store_source(source)
                logger.info("Fetched %d certs from %s (%s)", len(certs), source.url, label)
                cert_lists.append((label, certs))
            except Exception as e:
                logger.error("Failed to fetch %s: %s", source.url, e)

    if not cert_lists or not any(certs for _, certs in cert_lists):
        raise RuntimeError("No certificates fetched from any provider source")

    pem_bundle, stats = merge_and_deduplicate(cert_lists, filter_fn=filter_fn)

    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(pem_bundle)
        logger.info("CA bundle written to %s", output_path)

    return pem_bundle, stats
