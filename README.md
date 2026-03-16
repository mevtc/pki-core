# pki-core

Generic X.509 certificate utilities for PKI-enabled applications.

## Features

- **Certificate parsing** — load PEM/DER x509 certificates, extract policy OIDs, emails, SAN URIs/UUIDs, FASC-N, and fingerprints
- **Identity extraction** — parse certificate identity using a pluggable provider registry with callable CN parsers and ID selectors
- **CRL checking** — revocation checking with stale-while-revalidate file-backed cache and background refresh
- **Trust store management** — download, merge, and deduplicate CA bundles from provider-defined sources
- **Validation pipeline** — `validate_certificate()` composes identity extraction, expiry checking, and CRL revocation into a single call
- **Provider registry** — pluggable authentication provider definitions with OID matching and heuristic detection

## Installation

```bash
pip install pki-core
```

## Quick start

```python
from pki_core.validation import validate_certificate, CertificatePolicy, ValidationStatus
from pki_core.certificate import load_certificate

cert = load_certificate(pem_bytes)
result = validate_certificate(cert)

if result.status == ValidationStatus.VALID:
    print(f"Valid: {result.identity.cn}")
elif result.status == ValidationStatus.EXPIRED:
    print("Certificate has expired")
elif result.status == ValidationStatus.REVOKED:
    print("Certificate has been revoked")
```

### With a custom provider

```python
from pki_core.providers import AuthProvider, ProviderRegistry, HeuristicRule
from pki_core.selectors import select_email_first
from pki_core.validation import CertificatePolicy, validate_certificate

def parse_company_cn(identity):
    # Custom CN parsing logic
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

## For federal PKI

Use [federal-pki](https://github.com/mevtc/federal-pki) which builds on pki-core with DoD CAC, Federal PIV, and ECA provider definitions.

## License

BSD-3-Clause — see [LICENSE](LICENSE).
