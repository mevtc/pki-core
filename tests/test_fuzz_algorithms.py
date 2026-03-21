"""Hypothesis fuzz tests for algorithm policy enforcement.

Property-based tests that throw random AlgorithmPolicy configurations at
check_algorithms() to verify it never crashes and always returns the
correct (bool, str) tuple.

Example counts are controlled by Hypothesis profiles registered in
conftest.py.  Use ``--hypothesis-profile=ci`` or ``--hypothesis-profile=nightly``
to increase coverage.
"""

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from pki.core.algorithms import AlgorithmPolicy, check_algorithms

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# All curve names that could realistically appear
curve_names = st.sampled_from(
    [
        "secp256r1",
        "secp384r1",
        "secp521r1",
        "secp256k1",
        "brainpoolP256r1",
        "brainpoolP384r1",
        "ed25519",
        "ed448",
    ]
)

hash_names = st.sampled_from(
    [
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "md5",
        "sha1",
    ]
)

# Random AlgorithmPolicy values
random_policy = st.builds(
    AlgorithmPolicy,
    min_rsa_bits=st.one_of(
        st.just(0),
        st.integers(min_value=512, max_value=16384),
    ),
    allowed_curves=st.frozensets(curve_names, min_size=0, max_size=5),
    allowed_hashes=st.frozensets(hash_names, min_size=0, max_size=5),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_check_result(result):
    """Verify check_algorithms() return type invariants."""
    assert isinstance(result, tuple), f"Expected tuple, got {type(result)}"
    assert len(result) == 2, f"Expected 2-tuple, got {len(result)}-tuple"
    passed, detail = result
    assert isinstance(passed, bool), f"First element should be bool, got {type(passed)}"
    assert isinstance(detail, str), f"Second element should be str, got {type(detail)}"


# ---------------------------------------------------------------------------
# check_algorithms with random policies against real certs
# ---------------------------------------------------------------------------


class TestFuzzCheckAlgorithms:
    @given(policy=random_policy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_cac_cert_never_crashes(self, cac_cert, policy):
        """Random policies against a CAC cert should never crash."""
        result = check_algorithms(cac_cert, policy)
        _assert_check_result(result)

    @given(policy=random_policy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_piv_cert_never_crashes(self, piv_cert, policy):
        """Random policies against a PIV cert should never crash."""
        result = check_algorithms(piv_cert, policy)
        _assert_check_result(result)

    @given(policy=random_policy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_ca_cert_never_crashes(self, ca_cert, policy):
        """Random policies against a CA cert should never crash."""
        result = check_algorithms(ca_cert, policy)
        _assert_check_result(result)

    @given(policy=random_policy)
    @settings(suppress_health_check=[HealthCheck.too_slow])
    def test_expired_cert_never_crashes(self, expired_cert, policy):
        """Random policies against an expired cert should never crash."""
        result = check_algorithms(expired_cert, policy)
        _assert_check_result(result)


class TestFuzzCheckAlgorithmsDefaults:
    def test_default_policy_passes_valid_rsa_cert(self, cac_cert):
        """A 2048-bit RSA cert with SHA-256 should pass the default policy."""
        result = check_algorithms(cac_cert, AlgorithmPolicy())
        _assert_check_result(result)
        passed, _ = result
        assert passed is True

    def test_zero_rsa_rejects_rsa_cert(self, cac_cert):
        """Setting min_rsa_bits=0 should reject RSA keys."""
        policy = AlgorithmPolicy(min_rsa_bits=0)
        result = check_algorithms(cac_cert, policy)
        _assert_check_result(result)
        passed, _ = result
        assert passed is False

    def test_high_min_rsa_rejects_2048(self, cac_cert):
        """Setting min_rsa_bits=4096 should reject a 2048-bit key."""
        policy = AlgorithmPolicy(min_rsa_bits=4096)
        result = check_algorithms(cac_cert, policy)
        _assert_check_result(result)
        passed, _ = result
        assert passed is False

    def test_empty_hashes_rejects(self, cac_cert):
        """No allowed hashes should reject any cert."""
        policy = AlgorithmPolicy(allowed_hashes=frozenset())
        result = check_algorithms(cac_cert, policy)
        _assert_check_result(result)
        passed, _ = result
        assert passed is False


class TestFuzzCheckAlgorithmsInvariants:
    @given(
        min_rsa=st.integers(min_value=1, max_value=2048),
    )
    def test_rsa_at_or_below_keysize_passes(self, cac_cert, min_rsa):
        """Any min_rsa_bits <= 2048 should pass for a 2048-bit RSA cert."""
        policy = AlgorithmPolicy(
            min_rsa_bits=min_rsa,
            allowed_hashes=frozenset({"sha256", "sha384", "sha512"}),
        )
        result = check_algorithms(cac_cert, policy)
        _assert_check_result(result)
        passed, _ = result
        assert passed is True

    @given(
        min_rsa=st.integers(min_value=2049, max_value=16384),
    )
    def test_rsa_above_keysize_fails(self, cac_cert, min_rsa):
        """Any min_rsa_bits > 2048 should fail for a 2048-bit RSA cert."""
        policy = AlgorithmPolicy(
            min_rsa_bits=min_rsa,
            allowed_hashes=frozenset({"sha256", "sha384", "sha512"}),
        )
        result = check_algorithms(cac_cert, policy)
        _assert_check_result(result)
        passed, _ = result
        assert passed is False
