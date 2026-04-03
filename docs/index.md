# pki-core

Generic X.509 certificate utilities for PKI-enabled applications.

## Overview

pki-core is a PKI framework with a pluggable provider system. It handles
certificate parsing, identity extraction, chain validation, revocation
checking, algorithm enforcement, and trust store management.

**Provider packs** supply ecosystem-specific definitions (OIDs, CN parsers,
trust store sources) while pki-core handles the generic infrastructure.

```
pki.core              <- framework (this package)
pki.federal           <- DoD CAC / Federal PIV / ECA provider pack
pki.mycorp            <- your organization's provider pack
```

All packages share the `pki` namespace via Python's implicit namespace
packages (PEP 420). Each is installed independently.

## Features

- **Certificate parsing** -- load PEM/DER x509 certificates, extract policy OIDs, emails, SAN URIs/UUIDs, FASC-N, and fingerprints
- **Identity extraction** -- parse certificate identity using a pluggable provider registry with callable CN parsers and ID selectors
- **Chain validation** -- RFC 5280 certificate path validation via `verify_chain()`
- **Revocation checking** -- pluggable strategies (`CRL`, `OCSP`) with configurable order and fallback
- **Algorithm enforcement** -- `AlgorithmPolicy` validates key type/size and signature hash
- **Trust store management** -- download, merge, and deduplicate CA bundles from provider-defined sources
- **Validation pipeline** -- `validate_certificate()` composes chain validation, algorithm checking, identity extraction, expiry, and revocation into a single call
- **Provider registry** -- pluggable authentication provider definitions with OID matching and heuristic detection

## Installation

```bash
pip install pki-core
```

## Available Provider Packs

- [pki-federal](https://github.com/mevtc/pki-federal) -- DoD CAC, Federal PIV, and ECA

## License

BSD-3-Clause
