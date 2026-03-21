"""Tests for pki.core.algorithms — algorithm policy enforcement."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pki.core.algorithms import AlgorithmPolicy, check_algorithms
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate

_DEFAULT_HASH = hashes.SHA256()


def _self_signed(key, hash_alg=_DEFAULT_HASH):
    """Build a minimal self-signed cert from *key* using *hash_alg*."""
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Algorithm Test")])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hash_alg)
    )


@pytest.fixture(scope="module")
def rsa_2048_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _self_signed(key)


@pytest.fixture(scope="module")
def rsa_4096_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    return _self_signed(key)


@pytest.fixture(scope="module")
def ec_p256_cert():
    key = ec.generate_private_key(ec.SECP256R1())
    return _self_signed(key)


@pytest.fixture(scope="module")
def ec_p384_cert():
    key = ec.generate_private_key(ec.SECP384R1())
    return _self_signed(key, hashes.SHA384())


@pytest.fixture(scope="module")
def ec_p521_cert():
    key = ec.generate_private_key(ec.SECP521R1())
    return _self_signed(key, hashes.SHA512())


@pytest.fixture(scope="module")
def rsa_sha512_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _self_signed(key, hashes.SHA512())


# ---------------------------------------------------------------------------
# AlgorithmPolicy defaults
# ---------------------------------------------------------------------------


class TestAlgorithmPolicyDefaults:
    def test_default_min_rsa(self):
        assert AlgorithmPolicy().min_rsa_bits == 2048

    def test_default_curves(self):
        assert AlgorithmPolicy().allowed_curves == frozenset({"secp256r1", "secp384r1"})

    def test_default_hashes(self):
        assert AlgorithmPolicy().allowed_hashes == frozenset({"sha256", "sha384", "sha512"})

    def test_frozen(self):
        """AlgorithmPolicy is immutable."""
        policy = AlgorithmPolicy()
        with pytest.raises(AttributeError):
            policy.min_rsa_bits = 4096


# ---------------------------------------------------------------------------
# check_algorithms — RSA
# ---------------------------------------------------------------------------


class TestCheckAlgorithmsRSA:
    def test_rsa_2048_passes_default(self, rsa_2048_cert):
        passed, _detail = check_algorithms(rsa_2048_cert, AlgorithmPolicy())
        assert passed

    def test_rsa_4096_passes_default(self, rsa_4096_cert):
        passed, _detail = check_algorithms(rsa_4096_cert, AlgorithmPolicy())
        assert passed

    def test_rsa_2048_fails_3072_minimum(self, rsa_2048_cert):
        policy = AlgorithmPolicy(min_rsa_bits=3072)
        passed, detail = check_algorithms(rsa_2048_cert, policy)
        assert not passed
        assert "2048" in detail
        assert "3072" in detail

    def test_rsa_rejected_when_disallowed(self, rsa_2048_cert):
        policy = AlgorithmPolicy(min_rsa_bits=0)
        passed, detail = check_algorithms(rsa_2048_cert, policy)
        assert not passed
        assert "not allowed" in detail.lower()


# ---------------------------------------------------------------------------
# check_algorithms — ECC
# ---------------------------------------------------------------------------


class TestCheckAlgorithmsECC:
    def test_p256_passes_default(self, ec_p256_cert):
        passed, _detail = check_algorithms(ec_p256_cert, AlgorithmPolicy())
        assert passed

    def test_p384_passes_default(self, ec_p384_cert):
        passed, _detail = check_algorithms(ec_p384_cert, AlgorithmPolicy())
        assert passed

    def test_p521_fails_default(self, ec_p521_cert):
        """P-521 is not in the default allowed set."""
        passed, detail = check_algorithms(ec_p521_cert, AlgorithmPolicy())
        assert not passed
        assert "secp521r1" in detail.lower()

    def test_p521_passes_when_allowed(self, ec_p521_cert):
        policy = AlgorithmPolicy(allowed_curves=frozenset({"secp256r1", "secp384r1", "secp521r1"}))
        passed, _detail = check_algorithms(ec_p521_cert, policy)
        assert passed

    def test_p384_only(self, ec_p256_cert, ec_p384_cert):
        policy = AlgorithmPolicy(allowed_curves=frozenset({"secp384r1"}))
        passed_256, _ = check_algorithms(ec_p256_cert, policy)
        passed_384, _ = check_algorithms(ec_p384_cert, policy)
        assert not passed_256
        assert passed_384


# ---------------------------------------------------------------------------
# check_algorithms — hash
# ---------------------------------------------------------------------------


class TestCheckAlgorithmsHash:
    def test_sha256_passes_default(self, rsa_2048_cert):
        passed, _ = check_algorithms(rsa_2048_cert, AlgorithmPolicy())
        assert passed

    def test_sha512_rejected_by_restrictive_policy(self, rsa_sha512_cert):
        """SHA-512 passes default but fails a SHA-384-only policy."""
        policy = AlgorithmPolicy(allowed_hashes=frozenset({"sha384"}))
        passed, detail = check_algorithms(rsa_sha512_cert, policy)
        assert not passed
        assert "sha512" in detail.lower()

    def test_sha256_rejected_by_restrictive_policy(self, rsa_2048_cert):
        """SHA-256 cert fails when only SHA-384/512 are allowed."""
        policy = AlgorithmPolicy(allowed_hashes=frozenset({"sha384", "sha512"}))
        passed, detail = check_algorithms(rsa_2048_cert, policy)
        assert not passed
        assert "sha256" in detail.lower()

    def test_sha384_passes(self, ec_p384_cert):
        passed, _ = check_algorithms(ec_p384_cert, AlgorithmPolicy())
        assert passed


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------


class TestValidateCertificateAlgorithms:
    def test_compliant_cert(self, rsa_2048_cert):
        policy = CertificatePolicy(
            algorithm_policy=AlgorithmPolicy(),
            revocation=None,
        )
        result = validate_certificate(rsa_2048_cert, policy)
        assert result.status == ValidationStatus.VALID

    def test_noncompliant_cert(self, ec_p521_cert):
        """P-521 is not in the default allowed curves."""
        policy = CertificatePolicy(
            algorithm_policy=AlgorithmPolicy(),
            revocation=None,
        )
        result = validate_certificate(ec_p521_cert, policy)
        assert result.status == ValidationStatus.ALGORITHM_NONCOMPLIANT
        assert "secp521r1" in result.error.lower()
        # Identity should still be populated for logging
        assert result.identity is not None

    def test_none_skips_check(self, ec_p521_cert):
        """algorithm_policy=None (default) skips algorithm checking."""
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(ec_p521_cert, policy)
        assert result.status == ValidationStatus.VALID
