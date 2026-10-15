"""Tests for pki.core._http.fetch_bytes — bounded, streamed fetching."""

import gzip
from unittest.mock import patch

import httpx
import pytest

from pki.core import _http
from pki.core._http import fetch_bytes


def _serve(handler):
    """Route fetch_bytes through an in-process MockTransport."""
    return patch.object(
        _http,
        "_client",
        lambda timeout, follow_redirects: httpx.Client(
            transport=httpx.MockTransport(handler), follow_redirects=follow_redirects
        ),
    )


def test_returns_body():
    with _serve(lambda req: httpx.Response(200, content=iter([b"crl-bytes"]))):
        assert fetch_bytes("http://x/a.crl", max_bytes=100, timeout=5) == b"crl-bytes"


def test_requests_identity_encoding():
    seen = {}

    def handler(req):
        seen.update(req.headers)
        return httpx.Response(200, content=iter([b"ok"]))

    with _serve(handler):
        fetch_bytes("http://x/a.crl", max_bytes=100, timeout=5)
    assert seen["accept-encoding"] == "identity"


def test_declared_length_over_limit_rejected_before_reading():
    with (
        _serve(lambda req: httpx.Response(200, headers={"Content-Length": "999999"}, content=b"")),
        pytest.raises(ValueError, match="exceeds size limit"),
    ):
        fetch_bytes("http://x/a.crl", max_bytes=100, timeout=5)


def test_streamed_body_over_limit_rejected():
    def chunks():
        for _ in range(1000):
            yield b"x" * 1024

    # No Content-Length: the limit must be enforced while streaming.
    with (
        _serve(lambda req: httpx.Response(200, content=chunks())),
        pytest.raises(ValueError, match="exceeds size limit"),
    ):
        fetch_bytes("http://x/a.crl", max_bytes=10 * 1024, timeout=5)


def test_compressed_body_refused():
    """A gzip body is refused rather than decompressed past the limit."""
    bomb = gzip.compress(b"\0" * (5 * 1024 * 1024))
    with (
        _serve(lambda req: httpx.Response(200, headers={"Content-Encoding": "gzip"}, content=bomb)),
        pytest.raises(ValueError, match="Refusing encoded response"),
    ):
        fetch_bytes("http://x/a.crl", max_bytes=len(bomb) * 2, timeout=5)


def test_deadline_bounds_slow_transfer():
    def slow_chunks():
        import time

        for _ in range(50):
            time.sleep(0.05)
            yield b"x"

    with (
        _serve(lambda req: httpx.Response(200, content=slow_chunks())),
        pytest.raises(ValueError, match="deadline"),
    ):
        fetch_bytes("http://x/a.crl", max_bytes=1000, timeout=0.5)


def test_http_error_status_raises():
    with (
        _serve(lambda req: httpx.Response(404)),
        pytest.raises(httpx.HTTPStatusError),
    ):
        fetch_bytes("http://x/a.crl", max_bytes=100, timeout=5)


def test_post_sends_body():
    seen = {}

    def handler(req):
        seen["method"], seen["body"] = req.method, req.content
        return httpx.Response(200, content=iter([b"resp"]))

    with _serve(handler):
        fetch_bytes("http://x/ocsp", method="POST", content=b"req", max_bytes=100, timeout=5)
    assert seen == {"method": "POST", "body": b"req"}
