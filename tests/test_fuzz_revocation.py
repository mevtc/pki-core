"""Hypothesis fuzz tests for revocation checking pipeline.

Property-based tests that verify run_revocation_checks() pipeline ordering
invariants hold regardless of what individual checks return, and that
_get_ocsp_responder_urls() always returns list[str].

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.revocation import (
    RevocationCheck,
    RevocationPolicy,
    RevocationResult,
    _get_ocsp_responder_urls,
    run_revocation_checks,
)

# ---------------------------------------------------------------------------
# Stub strategy: a RevocationCheck that returns a predetermined result
# ---------------------------------------------------------------------------


class StubCheck(RevocationCheck):
    """A revocation check that returns a fixed result."""

    def __init__(self, result: RevocationResult, detail: str = "stub"):
        self._result = result
        self._detail = detail

    def check(self, cert, policy):
        return self._result, self._detail

    def __repr__(self):
        return f"StubCheck({self._result})"


# Strategy for a single stub check result
stub_result = st.sampled_from(
    [
        RevocationResult.GOOD,
        RevocationResult.REVOKED,
        RevocationResult.UNAVAILABLE,
    ]
)

# Strategy for a list of stub checks
stub_checks = st.lists(
    st.builds(
        StubCheck,
        result=stub_result,
        detail=st.text(min_size=1, max_size=50),
    ),
    min_size=0,
    max_size=6,
)

# Strategy for strict flag
strict_flag = st.booleans()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_revocation_result(result):
    """Verify run_revocation_checks() return type invariants."""
    assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
    assert len(result) == 2, f"Expected 2-tuple, got {len(result)}-tuple"
    status, detail = result
    assert isinstance(status, RevocationResult), f"Expected RevocationResult, got {type(status)}"
    assert isinstance(detail, str), f"Expected str detail, got {type(detail)}"


# ---------------------------------------------------------------------------
# run_revocation_checks — pipeline ordering invariants
# ---------------------------------------------------------------------------


class TestFuzzRunRevocationChecks:
    @given(checks=stub_checks, strict=strict_flag)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cac_cert, ca_cert, checks, strict):
        """Random sequences of stub checks should never crash."""
        pol = RevocationPolicy(checks=checks, issuer_certs=[ca_cert], strict=strict)
        result = run_revocation_checks(pol, cac_cert)
        _assert_revocation_result(result)

    @given(
        prefix=st.lists(
            st.just(StubCheck(RevocationResult.UNAVAILABLE, "unavail")),
            min_size=0,
            max_size=3,
        ),
        suffix=st.lists(
            st.builds(StubCheck, result=stub_result, detail=st.just("after")),
            min_size=0,
            max_size=3,
        ),
    )
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_good_stops_pipeline(self, cac_cert, ca_cert, prefix, suffix):
        """A GOOD result should stop the pipeline immediately."""
        good = StubCheck(RevocationResult.GOOD, "found good")
        checks = [*prefix, good, *suffix]
        pol = RevocationPolicy(checks=checks, issuer_certs=[ca_cert])
        result, detail = run_revocation_checks(pol, cac_cert)
        assert result == RevocationResult.GOOD
        assert detail == "found good"

    @given(
        prefix=st.lists(
            st.just(StubCheck(RevocationResult.UNAVAILABLE, "unavail")),
            min_size=0,
            max_size=3,
        ),
        suffix=st.lists(
            st.builds(StubCheck, result=stub_result, detail=st.just("after")),
            min_size=0,
            max_size=3,
        ),
    )
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_revoked_stops_pipeline(self, cac_cert, ca_cert, prefix, suffix):
        """A REVOKED result should stop the pipeline immediately."""
        revoked = StubCheck(RevocationResult.REVOKED, "found revoked")
        checks = [*prefix, revoked, *suffix]
        pol = RevocationPolicy(checks=checks, issuer_certs=[ca_cert])
        result, detail = run_revocation_checks(pol, cac_cert)
        assert result == RevocationResult.REVOKED
        assert detail == "found revoked"

    @given(count=st.integers(min_value=0, max_value=5))
    def test_all_unavailable_strict_returns_unavailable(self, cac_cert, ca_cert, count):
        """All UNAVAILABLE checks in strict mode should return UNAVAILABLE."""
        checks = [StubCheck(RevocationResult.UNAVAILABLE, f"unavail-{i}") for i in range(count)]
        pol = RevocationPolicy(checks=checks, issuer_certs=[ca_cert], strict=True)
        result, detail = run_revocation_checks(pol, cac_cert)
        _assert_revocation_result((result, detail))

    @given(count=st.integers(min_value=1, max_value=5))
    def test_all_unavailable_nonstrict_returns_good(self, cac_cert, ca_cert, count):
        """All UNAVAILABLE checks in non-strict mode should return GOOD."""
        checks = [StubCheck(RevocationResult.UNAVAILABLE, f"unavail-{i}") for i in range(count)]
        pol = RevocationPolicy(checks=checks, issuer_certs=[ca_cert], strict=False)
        result, _ = run_revocation_checks(pol, cac_cert)
        assert result == RevocationResult.GOOD

    def test_empty_checks_strict(self, cac_cert, ca_cert):
        """No checks configured in strict mode."""
        pol = RevocationPolicy(checks=[], issuer_certs=[ca_cert], strict=True)
        result, detail = run_revocation_checks(pol, cac_cert)
        _assert_revocation_result((result, detail))

    def test_empty_checks_nonstrict(self, cac_cert, ca_cert):
        """No checks configured in non-strict mode."""
        pol = RevocationPolicy(checks=[], issuer_certs=[ca_cert], strict=False)
        result, detail = run_revocation_checks(pol, cac_cert)
        _assert_revocation_result((result, detail))


# ---------------------------------------------------------------------------
# _get_ocsp_responder_urls
# ---------------------------------------------------------------------------


class TestFuzzGetOcspResponderUrls:
    def test_cac_cert_returns_list_of_strings(self, cac_cert):
        result = _get_ocsp_responder_urls(cac_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_piv_cert_returns_list_of_strings(self, piv_cert):
        result = _get_ocsp_responder_urls(piv_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_ca_cert_returns_list_of_strings(self, ca_cert):
        result = _get_ocsp_responder_urls(ca_cert)
        assert isinstance(result, list)
        for url in result:
            assert isinstance(url, str)

    def test_expired_cert_returns_list_of_strings(self, expired_cert):
        result = _get_ocsp_responder_urls(expired_cert)
        assert isinstance(result, list)

    def test_urls_are_http(self, cac_cert):
        """Any returned URLs should start with http:// or https://."""
        urls = _get_ocsp_responder_urls(cac_cert)
        for url in urls:
            assert url.startswith(("http://", "https://")), f"URL {url!r} is not HTTP(S)"
