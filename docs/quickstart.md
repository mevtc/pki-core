# Getting Started

This guide covers the basics of using pki-core to load certificates,
extract identity information, and run the validation pipeline.

## Installation

```bash
pip install pki-core
```

For Federal PKI support (DoD CAC, PIV, ECA), also install the provider pack:

```bash
pip install pki-federal
```

## Load a Certificate

pki-core can load certificates from PEM or DER-encoded bytes:

```python
from pki.core.certificate import load_certificate

# From PEM bytes
cert = load_certificate(pem_bytes)

# Access basic certificate fields
print(cert.subject)
print(cert.not_valid_after_utc)
```

## Extract Identity

Use a `ProviderRegistry` to extract structured identity from a certificate.
The registry matches the certificate to a provider based on policy OIDs or
heuristic rules, then parses the CN and selects a primary identifier:

```python
from pki.core.identity import CertificateIdentity
from pki.core.providers import AuthProvider, ProviderRegistry
from pki.core.selectors import select_email_first

def parse_cn(identity):
    parts = identity.cn.split(" ")
    identity.firstname = parts[0]
    identity.lastname = parts[-1]

provider = AuthProvider(
    name="EXAMPLE",
    display_name="Example Corp",
    auth_oids=frozenset({"1.2.3.4.5.6"}),
    cn_parser=parse_cn,
    primary_id_selector=select_email_first,
)

registry = ProviderRegistry()
registry.register(provider)
```

## Validate a Certificate

The simplest validation checks expiry and extracts identity:

```python
from pki.core.certificate import load_certificate
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate

cert = load_certificate(pem_bytes)
result = validate_certificate(cert)

if result.status == ValidationStatus.VALID:
    print(f"Valid: {result.identity.cn}")
else:
    print(f"Failed: {result.status} -- {result.error}")
```

## Full Validation Pipeline

For production use, configure chain validation, algorithm enforcement, and
revocation checking:

```python
from pki.core.certificate import load_certificate
from pki.core.crl import CRLConfig, load_ca_certs_from_pem
from pki.core.revocation import CRL, OCSP, RevocationPolicy
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate

cert = load_certificate(pem_bytes)

# Load CA bundle
ca_certs = load_ca_certs_from_pem(open("/etc/pki/ca-bundle.pem", "rb").read())

policy = CertificatePolicy(
    check_chain=True,
    trust_store=ca_certs,
    revocation=RevocationPolicy(
        checks=(CRL, OCSP),
        issuer_certs=ca_certs,
        crl_config=CRLConfig(cache_dir="/var/cache/pki/crls", cache_ttl=3600),
        strict=True,
    ),
)

result = validate_certificate(cert, policy)

match result.status:
    case ValidationStatus.VALID:
        print(f"Identity: {result.identity.primary_id}")
    case ValidationStatus.CHAIN_UNTRUSTED:
        print(f"Untrusted chain: {result.error}")
    case ValidationStatus.EXPIRED:
        print(f"Expired: {result.error}")
    case ValidationStatus.REVOKED:
        print(f"Revoked: {result.error}")
    case _:
        print(f"Error: {result.error}")
```

## Check Revocation

You can also check revocation independently using the built-in `CRL` and
`OCSP` strategies, or implement your own by subclassing `RevocationCheck`:

```python
from pki.core.revocation import CRL, OCSP, RevocationCheck, RevocationPolicy, RevocationResult

class InternalCRLDatabase(RevocationCheck):
    """Check revocation against an internal database."""

    def check(self, cert, policy):
        serial = format(cert.serial_number, "x")
        if self._is_revoked(serial):
            return RevocationResult.REVOKED, f"Revoked in internal DB (serial {serial})"
        return RevocationResult.GOOD, "Not revoked in internal DB"

    def _is_revoked(self, serial):
        ...  # query your database

# Internal DB first, then CRL, then OCSP
policy = CertificatePolicy(
    revocation=RevocationPolicy(checks=(InternalCRLDatabase(), CRL, OCSP)),
)
```

## Algorithm Enforcement

Use `AlgorithmPolicy` to reject certificates with weak algorithms:

```python
from pki.core.algorithms import AlgorithmPolicy

policy = AlgorithmPolicy(
    allowed_key_types={"rsa", "ec"},
    min_rsa_bits=2048,
    allowed_ec_curves={"secp256r1", "secp384r1"},
    allowed_hashes={"sha256", "sha384", "sha512"},
)
```

## Next Steps

- Browse the [API Reference](api/index.md) for detailed module documentation
- See [pki-federal](https://github.com/mevtc/pki-federal) for a real-world provider pack
