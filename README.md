# pki-core

Generic X.509 certificate utilities for PKI-enabled applications.

## Features

- **Certificate parsing** — load PEM/DER x509 certificates, extract policy OIDs, emails, SAN URIs/UUIDs, FASC-N, and fingerprints
- **Identity extraction** — parse certificate identity using a pluggable provider registry with callable CN parsers and ID selectors
- **Chain validation** — RFC 5280 certificate path validation via `verify_chain()`
- **Revocation checking** — pluggable strategies (`CRL`, `OCSP`) with configurable order and fallback
- **Algorithm enforcement** — `AlgorithmPolicy` validates key type/size and signature hash
- **Trust store management** — download, merge, and deduplicate CA bundles from provider-defined sources
- **Validation pipeline** — `validate_certificate()` composes chain validation, algorithm checking, identity extraction, expiry, and revocation into a single call
- **Provider registry** — pluggable authentication provider definitions with OID matching and heuristic detection

## Architecture

pki-core is a PKI framework with a pluggable provider system. **Provider packs** supply ecosystem-specific definitions (OIDs, CN parsers, trust store sources) while pki-core handles the generic infrastructure.

```
pki.core              ← framework (this package)
pki.federal           ← DoD CAC / Federal PIV / ECA provider pack
pki.mycorp            ← your organization's provider pack
```

All packages share the `pki` namespace via Python's implicit namespace packages (PEP 420). Each is installed independently.

## Installation

```bash
pip install pki-core
```

## Examples

### Minimal — parse and validate a certificate

The simplest usage: load a certificate, check expiry, and extract identity.

```python
from pki.core.certificate import load_certificate
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate

cert = load_certificate(pem_bytes)
result = validate_certificate(cert)

if result.status == ValidationStatus.VALID:
    print(f"Valid: {result.identity.cn}")
else:
    print(f"Failed: {result.status} — {result.error}")
```

### Full — chain validation, algorithm policy, CRL + OCSP, Federal PKI

A production configuration using pki-federal with all validation steps enabled.

```python
from pki.core.certificate import load_certificate
from pki.core.crl import CRLConfig, load_ca_certs_from_pem
from pki.core.revocation import CRL, OCSP, RevocationPolicy
from pki.core.validation import CertificatePolicy, ValidationStatus, validate_certificate
from pki.federal import SP800_78_ALGORITHM_POLICY, default_registry

# Load the certificate
cert = load_certificate(pem_bytes)

# Load CA bundle (built from build_ca_bundle_for_providers() or downloaded)
ca_certs = load_ca_certs_from_pem(open("/etc/pki/ca-bundle.pem", "rb").read())

# Configure the full validation pipeline
policy = CertificatePolicy(
    # Step 0: RFC 5280 chain validation
    check_chain=True,
    trust_store=ca_certs,

    # Step 0b: SP 800-78 algorithm enforcement
    algorithm_policy=SP800_78_ALGORITHM_POLICY,

    # Step 1: Identity extraction with Federal PKI providers (CAC + PIV)
    registry=default_registry(),

    # Step 2: Validity period (enabled by default)
    check_validity_period=True,

    # Step 3: Revocation — try CRL first, fall back to OCSP
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
        print(f"Credential: {result.identity.credential_type}")
        print(f"Name: {result.identity.firstname} {result.identity.lastname}")
    case ValidationStatus.CHAIN_UNTRUSTED:
        print(f"Untrusted chain: {result.error}")
    case ValidationStatus.ALGORITHM_NONCOMPLIANT:
        print(f"Algorithm rejected: {result.error}")
    case ValidationStatus.EXPIRED:
        print(f"Expired: {result.error}")
    case ValidationStatus.REVOKED:
        print(f"Revoked: {result.error}")
    case _:
        print(f"Error: {result.error}")
```

### Custom revocation strategy

Implement `RevocationCheck` to add your own revocation source:

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

## Configuration architecture

The validation pipeline is configured through three nested dataclasses,
each owning a distinct concern:

```
CertificatePolicy                      ← top-level pipeline config
├── check_chain: bool                  ← chain validation on/off
├── trust_store: list[Certificate]     ← root CAs for chain validation
├── algorithm_policy: AlgorithmPolicy  ← key/hash requirements (opt-in)
├── registry: ProviderRegistry         ← identity extraction providers
│
└── revocation: RevocationPolicy       ← revocation checking (or None to skip)
    ├── checks: Sequence[RevocationCheck]  ← ordered strategies (CRL, OCSP, custom)
    ├── issuer_certs: list[Certificate]    ← CAs for CRL sig verification + OCSP requests
    ├── strict: bool                       ← fail-closed when all checks unavailable
    │
    └── crl_config: CRLConfig              ← cache mechanics
        ├── cache_dir: str                 ← where to store cached CRLs
        ├── cache_ttl: int                 ← seconds before stale (triggers background refresh)
        ├── max_crl_bytes: int             ← reject CRLs larger than this
        ├── max_acceptable_age: int        ← force-refresh if older than this
        └── fetch_timeout: int             ← HTTP timeout
```

**`CertificatePolicy`** owns the pipeline — which steps to run and in what order.

**`RevocationPolicy`** owns the security decisions — which strategies to try, what CA certs to use, and whether to fail open or closed. It is separate from `CertificatePolicy` so it can be shared across multiple validation calls or constructed independently.

**`CRLConfig`** owns the cache mechanics — where files are stored, how long they're fresh, size limits. Provider packs like `pki-federal` subclass it to set deployment-specific defaults (e.g., 20 MB max for DoD CRLs, 18-hour max age per FIPS 201-3).

## Validation pipeline

`validate_certificate()` runs these steps in order, short-circuiting on first failure:

| Step | Check | Controlled by | Status on failure |
|------|-------|---------------|-------------------|
| 0 | Chain validation | `check_chain`, `trust_store` | `CHAIN_UNTRUSTED` |
| 0b | Algorithm compliance | `algorithm_policy` | `ALGORITHM_NONCOMPLIANT` |
| 1 | Identity extraction | `registry` | `ERROR` |
| 2 | Validity period | `check_validity_period` | `NOT_YET_VALID` / `EXPIRED` |
| 3 | Revocation | `revocation` | `REVOKED` / `ERROR` |

Identity is populated even on failure (when possible) so callers can log who the failed certificate belonged to.

### Validation boundary

pki-core handles chain validation, identity extraction, algorithm enforcement, and revocation checking. The following must be handled by the TLS terminator (nginx, AWS ALB) or the application:

- **TLS challenge-response** — proof of private key possession (FIPS 201-3 §6.2.3.1 steps 3-6)
- **Certificate policy OID constraints in path building** — `cryptography`'s verifier does not support RFC 5280 §6.1.1 `initial-policy-set`. Use scoped trust stores and `get_policy_oids()` for post-validation policy checking.
- **Certificate Transparency** — SCT verification is not performed.

## Security

### FIPS 140 cryptographic module status

pki-core does not implement cryptographic primitives directly. All
cryptographic operations (signature verification, hash computation, CRL/OCSP
validation) are performed by the
[cryptography](https://cryptography.io/) library, which uses OpenSSL as its
backend.

**pki-core itself is not FIPS 140 validated.** FIPS 140 validation applies
to the underlying cryptographic module (OpenSSL), not to libraries that
call it. To deploy pki-core in a FIPS 140 compliant environment:

1. Use an OpenSSL build that has a FIPS 140 validation certificate
   (e.g., the OpenSSL FIPS Object Module or a vendor-validated build).
2. Ensure the FIPS provider is active in the OpenSSL configuration
   (`openssl list -providers` should show `fips`).
3. The `cryptography` library will automatically use the FIPS provider
   when OpenSSL is configured for FIPS mode.

The `AlgorithmPolicy` class (and `SP800_78_ALGORITHM_POLICY` in pki-federal)
enforces that certificates use approved algorithms (RSA 2048+, P-256/P-384,
SHA-256+), but this is an application-level check — it does not replace
FIPS 140 validation of the cryptographic module itself.

### SBOM

CycloneDX Software Bills of Materials are generated in CI on every pipeline
run and published as artifacts. SBOMs list all direct and transitive Python
dependencies with version numbers, enabling vulnerability tracking and
supply chain risk management per OMB M-22-18.

### NIST SP 800-53 controls

See [SP800-53-CONTROLS.md](SP800-53-CONTROLS.md) for a full mapping of
26 security controls to implementation evidence across the pki ecosystem.

pki-core directly implements:

- **IA-2(12)** — chain validation, FASC-N/UUID extraction, algorithm enforcement
- **IA-5 / IA-5(2)** — certificate lifecycle (expiration, revocation, path validation)
- **SC-12** — trust store management, secure CRL caching
- **SC-13** — cryptographic operations via FIPS-capable OpenSSL backend
- **SC-17** — certificate validation pipeline
- **SI-10** — input validation (certificate parsing, CRL size limits, algorithm checks)
- **SA-11 / SA-11(1) / SA-11(8)** — fuzz testing, static analysis, dependency scanning
- **SR-4 / CM-8** — CycloneDX SBOMs

### Security testing and static analysis

See [SECURITY.md](SECURITY.md) for vulnerability reporting, fuzz testing
coverage, and a full list of static analysis suppressions with
justifications.

## Provider packs

A provider pack defines `AuthProvider` instances for a specific PKI ecosystem. Each provider specifies:

- **auth_oids** — certificate policy OIDs that identify this credential type
- **cn_parser** — callable that extracts name fields from the certificate CN
- **primary_id_selector** — callable that picks the primary identifier (EDIPI, UUID, email, etc.)
- **heuristics** — fallback rules for matching certificates without recognized OIDs
- **trust_store_sources** — URLs and formats for downloading CA bundles

### Defining a custom provider

```python
from pki.core.providers import AuthProvider, ProviderRegistry, HeuristicRule
from pki.core.selectors import select_email_first

def parse_company_cn(identity):
    parts = identity.cn.split(" ")
    identity.firstname = parts[0]
    identity.lastname = parts[-1]

provider = AuthProvider(
    name="ACME",
    display_name="ACME Corp",
    auth_oids=frozenset({"1.2.3.4.5.6"}),
    cn_parser=parse_company_cn,
    primary_id_selector=select_email_first,
    heuristics=(HeuristicRule(field="org", pattern="acme"),),
)

registry = ProviderRegistry()
registry.register(provider)

policy = CertificatePolicy(registry=registry)
result = validate_certificate(cert, policy)
```

### Combining provider packs

```python
from pki.core.providers import ProviderRegistry
from pki.core.validation import CertificatePolicy, validate_certificate
from pki.federal import CAC_PROVIDER, PIV_PROVIDER
from pki.mycorp import MYCORP_PROVIDER

registry = ProviderRegistry()
registry.register(CAC_PROVIDER)
registry.register(PIV_PROVIDER)
registry.register(MYCORP_PROVIDER)

policy = CertificatePolicy(registry=registry)
result = validate_certificate(cert, policy)
```

### Creating a reusable provider pack

To distribute providers as a package, follow the same layout as [pki-federal](https://github.com/mevtc/pki-federal):

```
pki-mycorp/
├── src/pki/mycorp/
│   ├── __init__.py      # export provider instances
│   ├── oids.py          # policy OID constants
│   ├── cn_parsers.py    # CN parsing functions
│   ├── providers.py     # AuthProvider instances and registry factories
│   └── trust_store.py   # CA bundle fetchers (if applicable)
├── pyproject.toml       # depends on pki-core
└── tests/
```

No `pki/__init__.py` — use Python's implicit namespace packages so `pki.core`, `pki.federal`, and `pki.mycorp` coexist.

## Available provider packs

- [pki-federal](https://github.com/mevtc/pki-federal) — DoD CAC, Federal PIV, and ECA

## License

BSD-3-Clause — see [LICENSE](LICENSE).
