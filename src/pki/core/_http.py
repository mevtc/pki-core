"""Bounded HTTP fetching for revocation and trust-store downloads.

Every URL this library fetches is either taken from a certificate under
validation (CRL distribution points, OCSP responders) or served over plain
HTTP (DoD CRLs), so the response body is attacker-influenced.  Reading it with
``httpx.get(...).content`` buffers the whole body -- after transparently
decoding any ``Content-Encoding`` -- before a size check can run, and httpx's
timeout bounds only the gap between reads, not the transfer as a whole.

:func:`fetch_bytes` closes all three gaps: it streams the raw body and stops
at ``max_bytes``, refuses encoded bodies so a small compressed response
cannot expand in memory, and enforces ``timeout`` as a wall-clock deadline
for the entire request.
"""

from __future__ import annotations

import time

import httpx

_IDENTITY = {"", "identity"}


def _client(timeout: float, follow_redirects: bool) -> httpx.Client:
    """Return the client used for a single fetch (patched in tests)."""
    return httpx.Client(timeout=timeout, follow_redirects=follow_redirects)


def fetch_bytes(
    url: str,
    *,
    max_bytes: int,
    timeout: float,
    method: str = "GET",
    content: bytes | None = None,
    headers: dict[str, str] | None = None,
    follow_redirects: bool = True,
) -> bytes:
    """Fetch *url* and return the body, reading at most *max_bytes*.

    Args:
        url: URL to fetch.
        max_bytes: Largest body accepted.  The transfer is abandoned as soon
            as this is exceeded, so memory use is bounded by it.
        timeout: Wall-clock deadline in seconds for the whole transfer.
            It is also httpx's per-operation timeout, so a server that stops
            sending entirely is cut off at most one such timeout late.
        method: HTTP method.
        content: Request body, for POST.
        headers: Extra request headers.
        follow_redirects: Whether to follow redirects.

    Raises:
        ValueError: The body exceeds *max_bytes*, the transfer exceeds
            *timeout*, or the server sent an encoded body.
        httpx.HTTPError: Transport failure or non-2xx status.
    """
    request_headers = {"Accept-Encoding": "identity", **(headers or {})}
    deadline = time.monotonic() + timeout

    with (
        _client(timeout, follow_redirects) as client,
        client.stream(method, url, content=content, headers=request_headers) as resp,
    ):
        resp.raise_for_status()

        encoding = resp.headers.get("Content-Encoding", "").strip().lower()
        if encoding not in _IDENTITY:
            raise ValueError(f"Refusing encoded response from {url} (Content-Encoding: {encoding})")

        declared = resp.headers.get("Content-Length")
        if declared is not None and declared.isdecimal() and int(declared) > max_bytes:
            raise ValueError(
                f"Response from {url} exceeds size limit ({declared} > {max_bytes} bytes)"
            )

        chunks: list[bytes] = []
        received = 0
        for chunk in resp.iter_raw():
            received += len(chunk)
            if received > max_bytes:
                raise ValueError(f"Response from {url} exceeds size limit (> {max_bytes} bytes)")
            if time.monotonic() > deadline:
                raise ValueError(f"Response from {url} exceeded {timeout}s deadline")
            chunks.append(chunk)

    return b"".join(chunks)
