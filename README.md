# pki-core

Generic X.509 certificate utilities for PKI-enabled applications.

## Features

- **Certificate parsing** — load PEM/DER x509 certificates, extract policy OIDs, emails, SAN URIs/UUIDs, FASC-N, and fingerprints
- **Identity extraction** — parse certificate identity using a pluggable provider registry with callable CN parsers and ID selectors
- **CRL checking** — revocation checking with stale-while-revalidate file-backed cache and background refresh
- **Trust store management** — download, merge, and deduplicate CA bundles from provider-defined sources
- **Validation pipeline** — `validate_certificate()` composes identity extraction, expiry checking, and CRL revocation into a single call
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

## Quick start

```python
from pki.core.validation import validate_certificate, CertificatePolicy, ValidationStatus
from pki.core.certificate import load_certificate

cert = load_certificate(pem_bytes)
result = validate_certificate(cert)

if result.status == ValidationStatus.VALID:
    print(f"Valid: {result.identity.cn}")
elif result.status == ValidationStatus.EXPIRED:
    print("Certificate has expired")
elif result.status == ValidationStatus.REVOKED:
    print("Certificate has been revoked")
```

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
from pki.core.validation import CertificatePolicy, validate_certificate

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

An application can use multiple provider packs by registering providers from each:

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
