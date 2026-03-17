"""Tests for pki.core.selectors."""

from pki.core.identity import CertIdentity
from pki.core.selectors import select_edipi_first, select_email_first, select_uuid_first


class TestSelectEdipiFirst:
    def test_edipi_present(self):
        identity = CertIdentity(edipi="1234567890", subject_dn="CN=TEST")
        assert select_edipi_first(identity) == "edipi:1234567890"

    def test_uuid_fallback(self):
        identity = CertIdentity(
            piv_uuid="12345678-abcd-ef01-2345-6789abcdef01", subject_dn="CN=TEST"
        )
        assert select_edipi_first(identity) == "uuid:12345678-abcd-ef01-2345-6789abcdef01"

    def test_fascn_fallback(self):
        identity = CertIdentity(fascn="abc123", subject_dn="CN=TEST")
        assert select_edipi_first(identity) == "fascn:abc123"

    def test_dn_fallback(self):
        identity = CertIdentity(subject_dn="CN=TEST")
        assert select_edipi_first(identity) == "dn:CN=TEST"


class TestSelectUuidFirst:
    def test_uuid_present(self):
        identity = CertIdentity(
            piv_uuid="12345678-abcd-ef01-2345-6789abcdef01", edipi="999", subject_dn="CN=TEST"
        )
        assert select_uuid_first(identity) == "uuid:12345678-abcd-ef01-2345-6789abcdef01"

    def test_edipi_fallback(self):
        identity = CertIdentity(edipi="999", subject_dn="CN=TEST")
        assert select_uuid_first(identity) == "edipi:999"

    def test_dn_fallback(self):
        identity = CertIdentity(subject_dn="CN=TEST")
        assert select_uuid_first(identity) == "dn:CN=TEST"


class TestSelectEmailFirst:
    def test_email_present(self):
        identity = CertIdentity(email="user@example.com", subject_dn="CN=TEST")
        assert select_email_first(identity) == "email:user@example.com"

    def test_dn_fallback(self):
        identity = CertIdentity(subject_dn="CN=TEST")
        assert select_email_first(identity) == "dn:CN=TEST"
