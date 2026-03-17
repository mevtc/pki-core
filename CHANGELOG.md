# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2025-01-01

### Added

- X.509 certificate parsing with PEM/DER auto-detection
- Certificate identity extraction with pluggable provider registry
- Callable-based CN parsing and primary ID selection on AuthProvider
- CRL revocation checking with stale-while-revalidate file-backed cache
- CA trust store download, merge, and deduplication
- `validate_certificate()` pipeline composing identity, expiry, and CRL checks
- Primary ID selector functions: `select_edipi_first`, `select_uuid_first`, `select_email_first`
- `is_not_yet_valid()` check for premature certificates

### Origin

Extracted from [pki-federal](https://github.com/mevtc/pki-federal) to provide a PKI-agnostic base library.
