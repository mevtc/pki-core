# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `build_bundle_for_provider()` in `trust_store` — builds a PEM CA bundle for
  a single provider's trust store sources. Enables per-provider bundles for
  applications that need to know which provider matched (e.g., S/MIME milters
  verifying against multiple PKIs).
- Exported `build_bundle_for_provider` from `pki.core` public API.
- Test suite for `trust_store` module (`test_trust_store.py`).

## [0.2.0] - 2026-03-17

### Changed

- Restructured to `pki.core` namespace package (`src/pki/core/` layout)
- All imports changed from `pki_core.*` to `pki.core.*`
- Switched to `src` layout with implicit namespace package (PEP 420)

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
