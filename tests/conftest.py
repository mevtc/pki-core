"""Shared test fixtures: self-signed CA, signer cert, and CRL."""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def ca_key():
    return _generate_key()


@pytest.fixture(scope="session")
def ca_cert(ca_key):
    """Self-signed CA certificate."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test DoD CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Test DoD Root CA 1"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def ca_cert_pem(ca_cert):
    return ca_cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="session")
def signer_key():
    return _generate_key()


@pytest.fixture(scope="session")
def cac_cert(ca_key, ca_cert, signer_key):
    """End-entity certificate mimicking a DoD CAC (EDIPI in CN)."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SMITH.JOHN.A.1234567890"),
        ]
    )
    # DoD PIV Auth policy OID
    dod_policy = x509.PolicyInformation(x509.ObjectIdentifier("2.16.840.1.101.2.1.11.19"), None)
    # CRL distribution point
    crl_dp = x509.DistributionPoint(
        full_name=[x509.UniformResourceIdentifier("http://crl.test.example/test.crl")],
        relative_name=None,
        crl_issuer=None,
        reasons=None,
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.CertificatePolicies([dod_policy]), critical=False)
        .add_extension(x509.CRLDistributionPoints([crl_dp]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("john.smith@mail.mil"),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def piv_cert(ca_key, ca_cert, signer_key):
    """End-entity certificate mimicking a Federal PIV card."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Department of Energy"),
            x509.NameAttribute(NameOID.COMMON_NAME, "JONES, ALICE M"),
        ]
    )
    fpki_policy = x509.PolicyInformation(x509.ObjectIdentifier("2.16.840.1.101.3.2.1.3.13"), None)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.CertificatePolicies([fpki_policy]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("alice.jones@doe.gov"),
                    x509.UniformResourceIdentifier("urn:uuid:12345678-abcd-ef01-2345-6789abcdef01"),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def eca_cert(ca_key, ca_cert, signer_key):
    """End-entity certificate mimicking an ECA (contractor) certificate."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Contractor Corp"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "ECA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "John A. Smith"),
        ]
    )
    eca_policy = x509.PolicyInformation(x509.ObjectIdentifier("2.16.840.1.101.3.2.1.12.2"), None)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.CertificatePolicies([eca_policy]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.RFC822Name("john.smith@contractor.com"),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def bad_uuid_cert(ca_key, ca_cert, signer_key):
    """Certificate with a malformed UUID in SAN."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "BAD.UUID.CERT"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier("urn:uuid:not-a-valid-uuid"),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def expired_cert(ca_key, ca_cert, signer_key):
    """An expired certificate."""
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "EXPIRED.USER.X.9999999999"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(signer_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC))
        .sign(ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def revoked_serial(cac_cert):
    """Serial number to include in the test CRL as revoked."""
    return cac_cert.serial_number


@pytest.fixture(scope="session")
def wrong_ca_key():
    """A separate CA key for signature mismatch tests."""
    return _generate_key()


@pytest.fixture(scope="session")
def wrong_ca_cert(wrong_ca_key):
    """Self-signed CA certificate from a different authority."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Wrong CA Inc"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Wrong Root CA"),
        ]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(wrong_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(wrong_ca_key, hashes.SHA256())
    )


@pytest.fixture(scope="session")
def test_crl(ca_key, ca_cert, revoked_serial):
    """A CRL revoking the cac_cert."""
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime(2024, 6, 1, tzinfo=datetime.UTC))
    builder = builder.next_update(datetime.datetime(2030, 6, 1, tzinfo=datetime.UTC))
    revoked = (
        x509.RevokedCertificateBuilder()
        .serial_number(revoked_serial)
        .revocation_date(datetime.datetime(2024, 5, 1, tzinfo=datetime.UTC))
        .build()
    )
    builder = builder.add_revoked_certificate(revoked)
    return builder.sign(ca_key, hashes.SHA256())


@pytest.fixture(scope="session")
def expired_crl(ca_key, ca_cert):
    """A CRL whose nextUpdate is in the past."""
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
    builder = builder.next_update(datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC))
    return builder.sign(ca_key, hashes.SHA256())


@pytest.fixture(scope="session")
def test_crl_der(test_crl):
    """DER-encoded CRL bytes."""
    return test_crl.public_bytes(serialization.Encoding.DER)


@pytest.fixture(scope="session")
def test_crl_pem(test_crl):
    """PEM-encoded CRL bytes."""
    return test_crl.public_bytes(serialization.Encoding.PEM)
