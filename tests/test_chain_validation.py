"""Tests for RFC 5280 certificate chain validation."""

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

from pki.core.certificate import CertificateError
from pki.core.validation import (
    CertificatePolicy,
    ValidationStatus,
    validate_certificate,
    verify_chain,
)


class TestVerifyChain:
    def test_valid_direct(self, chain_ca_cert, chain_leaf_cert):
        """Leaf signed directly by root — chain length 2."""
        chain = verify_chain(chain_leaf_cert, [chain_ca_cert])
        assert len(chain) == 2

    def test_valid_with_intermediate(
        self, chain_ca_cert, chain_intermediate_cert, chain_leaf_via_intermediate_cert
    ):
        """Leaf → intermediate → root — chain length 3."""
        chain = verify_chain(
            chain_leaf_via_intermediate_cert,
            trust_store=[chain_ca_cert],
            intermediates=[chain_intermediate_cert],
        )
        assert len(chain) == 3

    def test_untrusted_root(self, chain_ca_cert, chain_leaf_from_untrusted):
        """Leaf signed by untrusted CA — should fail."""
        with pytest.raises(CertificateError, match="Chain validation failed"):
            verify_chain(chain_leaf_from_untrusted, [chain_ca_cert])

    def test_empty_store(self, chain_leaf_cert):
        """Empty trust store — should fail."""
        with pytest.raises(CertificateError, match="no self-signed root"):
            verify_chain(chain_leaf_cert, [])

    def test_expired_leaf(self, chain_ca_cert, chain_expired_leaf):
        """Expired leaf — verifier rejects as part of path validation."""
        with pytest.raises(CertificateError, match="Chain validation failed"):
            verify_chain(chain_expired_leaf, [chain_ca_cert])

    def test_missing_intermediate(self, chain_ca_cert, chain_leaf_via_intermediate_cert):
        """Leaf signed by intermediate, but intermediate not provided."""
        with pytest.raises(CertificateError, match="Chain validation failed"):
            verify_chain(chain_leaf_via_intermediate_cert, [chain_ca_cert])


class TestValidateCertificateChain:
    def test_chain_valid(self, chain_ca_cert, chain_leaf_cert):
        """Pipeline with check_chain=True, valid chain."""
        policy = CertificatePolicy(
            check_chain=True,
            trust_store=[chain_ca_cert],
            revocation=None,
        )
        result = validate_certificate(chain_leaf_cert, policy)
        assert result.status == ValidationStatus.VALID
        assert result.identity is not None
        assert result.chain is not None
        assert len(result.chain) == 2

    def test_chain_untrusted(self, chain_ca_cert, chain_leaf_from_untrusted):
        """Pipeline with check_chain=True, untrusted leaf."""
        policy = CertificatePolicy(
            check_chain=True,
            trust_store=[chain_ca_cert],
            revocation=None,
        )
        result = validate_certificate(chain_leaf_from_untrusted, policy)
        assert result.status == ValidationStatus.CHAIN_UNTRUSTED
        # Identity should still be populated for logging
        assert result.identity is not None
        assert result.identity.cn == "UNTRUSTED.LEAF.USER"

    def test_chain_no_store_error(self, chain_leaf_cert):
        """check_chain=True but trust_store=None — should error."""
        policy = CertificatePolicy(
            check_chain=True,
            trust_store=None,
            revocation=None,
        )
        result = validate_certificate(chain_leaf_cert, policy)
        assert result.status == ValidationStatus.ERROR
        assert "trust_store" in result.error

    def test_chain_disabled_by_default(self, cac_cert):
        """Default policy does not check chain (backward compat)."""
        policy = CertificatePolicy(revocation=None)
        result = validate_certificate(cac_cert, policy)
        assert result.status == ValidationStatus.VALID
        assert result.chain is None


class TestExpectedEKU:
    """EKU enforcement during chain validation.

    ``cryptography``'s ClientVerifier hard-codes an id-kp-clientAuth
    requirement.  S/MIME encryption certificates assert emailProtection
    alone, so they must not be rejected when the caller asks for S/MIME.
    """

    def test_encryption_cert_rejected_by_default(self, chain_ca_cert, smime_encryption_leaf):
        """Default (clientAuth) rejects an emailProtection-only cert."""
        with pytest.raises(CertificateError, match="Chain validation failed"):
            verify_chain(smime_encryption_leaf, [chain_ca_cert])

    def test_encryption_cert_accepted_for_smime(self, chain_ca_cert, smime_encryption_leaf):
        """emailProtection expectation accepts the S/MIME encryption cert."""
        chain = verify_chain(
            smime_encryption_leaf,
            [chain_ca_cert],
            expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
        )
        assert len(chain) == 2

    def test_signing_cert_accepted_both_ways(self, chain_ca_cert, smime_signing_leaf):
        """A cert asserting clientAuth + emailProtection satisfies either."""
        assert len(verify_chain(smime_signing_leaf, [chain_ca_cert])) == 2
        assert (
            len(
                verify_chain(
                    smime_signing_leaf,
                    [chain_ca_cert],
                    expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
                )
            )
            == 2
        )

    def test_wrong_eku_still_rejected(self, chain_ca_cert, server_auth_leaf):
        """serverAuth-only cert is rejected for both clientAuth and S/MIME."""
        with pytest.raises(CertificateError, match="Chain validation failed"):
            verify_chain(server_auth_leaf, [chain_ca_cert])
        with pytest.raises(CertificateError, match="Chain validation failed"):
            verify_chain(
                server_auth_leaf,
                [chain_ca_cert],
                expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
            )

    def test_eku_check_disabled(self, chain_ca_cert, server_auth_leaf):
        """expected_eku=None skips the EKU check entirely."""
        chain = verify_chain(server_auth_leaf, [chain_ca_cert], expected_eku=None)
        assert len(chain) == 2

    def test_absent_eku_is_unrestricted(self, chain_ca_cert, chain_leaf_cert):
        """A cert with no EKU extension satisfies any expected_eku (RFC 5280)."""
        assert len(verify_chain(chain_leaf_cert, [chain_ca_cert])) == 2
        assert (
            len(
                verify_chain(
                    chain_leaf_cert,
                    [chain_ca_cert],
                    expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
                )
            )
            == 2
        )

    def test_pipeline_threads_expected_eku(self, chain_ca_cert, smime_encryption_leaf):
        """CertificatePolicy.expected_eku reaches verify_chain."""
        reject = CertificatePolicy(check_chain=True, trust_store=[chain_ca_cert], revocation=None)
        assert (
            validate_certificate(smime_encryption_leaf, reject).status
            == ValidationStatus.CHAIN_UNTRUSTED
        )

        accept = CertificatePolicy(
            check_chain=True,
            trust_store=[chain_ca_cert],
            revocation=None,
            expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
        )
        assert validate_certificate(smime_encryption_leaf, accept).status == ValidationStatus.VALID
