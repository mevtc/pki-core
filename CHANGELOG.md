# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.3] - 2026-04-21

### Fixed

- **Security**: OCSP response signature is now verified per RFC 6960 Section
  3.2.  Previously, `_query_ocsp` trusted the parsed response status without
  verifying the response was signed by the issuer CA or a delegated OCSP
  responder with the id-kp-OCSPSigning EKU.  Supports both direct issuer
  signing and delegated responder certificates.
- **Security**: `prefetch_crls()` now creates the cache directory with
  `mode=0o700`, matching the permissions already used by `get_crl()`.
- **Security**: Hardened zip path traversal guard in `_fetch_pkcs7_zip()` to
  resolve extracted paths and verify they stay under the working directory.
- `extract_san_fascn()` now logs unexpected exceptions instead of silently
  swallowing them with a bare `except Exception`.

### Changed

- `ProviderRegistry.register()` pre-compiles regex patterns at registration
  time.  `match_heuristic()` uses cached compiled patterns instead of
  recompiling on every call.
- `USER_AGENT` in `trust_store.py` now reads the installed package version
  from `importlib.metadata` instead of a hardcoded string.

## [0.3.2] - 2026-04-08

### Fixed

- **Security**: `get_crl()` now verifies CRL signatures on cache load when
  `issuer_certs` is provided, not just on fetch.  Previously, a cached CRL
  was returned without signature verification, allowing an attacker with
  write access to the cache directory to substitute a forged CRL that omits
  revoked serials.  Cache directory permissions (0o700) and file permissions
  (0o600) remain the primary defense; this adds defense-in-depth.

### Changed

- `get_crl()` accepts an optional `issuer_certs` parameter.  When provided,
  CRL signature and freshness are verified on every load (cache hit or miss).
- `check_revocation()` now passes `issuer_certs` through to `get_crl()`
  instead of verifying the CRL separately after retrieval.

## [0.3.1] - 2026-04-03

### Added

- Automated PyPI publishing via trusted publisher (OIDC) in release workflow.

## [0.3.0] - 2026-03-21

### Added

- `verify_chain()` function for RFC 5280 certificate path validation using
  `cryptography.x509.verification.ClientVerifier`.
- `CHAIN_UNTRUSTED` status in `ValidationStatus`.
- `check_chain`, `trust_store`, and `intermediates` fields on `CertificatePolicy`.
- `chain` field on `ValidationResult` — populated with the validated chain on success.
- Chain validation as optional first step in `validate_certificate()` pipeline
  (opt-in via `check_chain=True`; backward-compatible default is `False`).
- Pluggable revocation checking via `RevocationCheck` ABC in `revocation.py`.
  Built-in strategies: `CRL` (file-backed cache) and `OCSP` (live query to AIA
  responder).
- `RevocationPolicy` dataclass grouping strategy ordering, issuer certificates,
  CRL cache config, and strictness into a single object.
- `RevocationResult` enum: `GOOD`, `REVOKED`, `UNAVAILABLE`.
- `run_revocation_checks()` pipeline runner with strict/non-strict fallback.
- `AlgorithmPolicy` frozen dataclass in `algorithms.py` for cryptographic
  algorithm enforcement (min RSA bits, allowed EC curves, allowed signature
  hashes).
- `check_algorithms()` function validates a certificate against a policy.
- `ALGORITHM_NONCOMPLIANT` status in `ValidationStatus`.
- `algorithm_policy` field on `CertificatePolicy` — opt-in (None by default).
- `max_crl_bytes` field on `CRLConfig` — configurable maximum CRL response
  size (default 10 MB).
- `max_acceptable_age` field on `CRLConfig` — maximum age in seconds of a
  cached CRL before it is force-refreshed synchronously instead of served stale.
- `build_bundle_for_provider()` in `trust_store` — builds a PEM CA bundle for
  a single provider's trust store sources.
- Exported `verify_chain`, `CRL`, `OCSP`, `RevocationCheck`, `RevocationPolicy`,
  `RevocationResult`, `AlgorithmPolicy`, `build_bundle_for_provider` from
  `pki.core` public API.
- NIST SP 800-53 Rev 5 controls mapping (`SP800-53-CONTROLS.md`).
- Hypothesis fuzz tests for certificate parsing, algorithms, revocation pipeline,
  identity extraction, selectors, providers, CRL parsing, and trust store.
- CycloneDX SBOM generation in CI.

### Changed

- `CertificatePolicy` revocation fields consolidated into `revocation:
  RevocationPolicy | None`.  Replaces `check_revocation`, `revocation_checks`,
  `issuer_certs`, and `crl_config`.  Set `revocation=None` to disable.
- `RevocationCheck.check()` now accepts `(cert, policy)` instead of
  `(cert, issuer_certs, config)`.
- `run_revocation_checks()` now accepts `(policy, cert)` instead of
  separate `checks`, `cert`, `issuer_certs`, `config`, `strict` arguments.
- `refresh_crl()` now accepts a `CRLConfig` instead of a bare `timeout` int.
- `CRLConfig` no longer has a module-level `MAX_CRL_BYTES` constant;
  use `config.max_crl_bytes` instead.

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
