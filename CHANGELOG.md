# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-08-11

Note for anyone upgrading from PyPI: 0.4.0 was tagged but never published,
so 0.3.4 is the previous release on PyPI and the 0.4.0 notes below apply to
this upgrade as well.

### Fixed

- **Chain validation no longer rejects S/MIME encryption certificates.**
  `verify_chain()` builds `cryptography`'s `ClientVerifier`, whose default
  end-entity extension policy hard-codes an `id-kp-clientAuth` requirement.
  Any certificate asserting an EKU that omits `clientAuth` failed path
  validation with `required EKU not found` — including every S/MIME
  encryption certificate, which asserts `id-kp-emailProtection` alone by
  profile (DoD CAC and ECA email encryption certificates both do).
  Callers saw `CHAIN_UNTRUSTED` for a perfectly valid certificate.

  A certificate carrying **no** EKU extension remains unrestricted per
  RFC 5280 §4.2.1.12 — which is why the existing chain fixtures, none of
  which asserted an EKU, never caught this.

### Added

- `expected_eku` parameter on `verify_chain()` and matching field on
  `CertificatePolicy`.  Defaults to `ExtendedKeyUsageOID.CLIENT_AUTH`,
  preserving existing behaviour for authentication callers.  Set to
  `ExtendedKeyUsageOID.EMAIL_PROTECTION` for S/MIME, or `None` to skip
  the EKU check.

  ```python
  from cryptography.x509.oid import ExtendedKeyUsageOID

  policy = CertificatePolicy(
      check_chain=True,
      trust_store=ca_certs,
      expected_eku=ExtendedKeyUsageOID.EMAIL_PROTECTION,
  )
  ```

  Implemented via `PolicyBuilder.extension_policies()`, retaining
  `webpki_defaults_ca()` and `webpki_defaults_ee()` for every other
  extension check rather than relaxing end-entity validation wholesale.

### Changed

- Documented the EKU requirement in the `verify_chain()` docstring and the
  module-level validation boundary.  The previous description of what
  `ClientVerifier` checks omitted EKU entirely.

## [0.4.0] - 2026-07-16

### Added

- `IntendedUse` Flag enum declaring what a provider's certificates are
  approved for: `PERSONAL_AUTH`, `NPE_AUTH`, `OBJECT_SIGNING`,
  `ENCRYPTION`, `TIMESTAMPING`.  A provider may set multiple bits
  when a single policy genuinely permits multiple uses.
- `intended_use` field on `AuthProvider` (defaults to
  `IntendedUse.PERSONAL_AUTH` for backward compatibility).
- `intended_use` constructor parameter on `ProviderRegistry`.  When
  set, `register()` refuses any provider whose `intended_use` does
  not include the constrained bits, turning mis-composition into a
  definition-time `ValueError` instead of a silent runtime security
  boundary violation.

  Consumers enforce intent at the boundary using set membership:

      if IntendedUse.PERSONAL_AUTH not in provider.intended_use:
          raise AuthError(...)

- `IntendedUse` is now exported from the top-level `pki.core` package.
- `intended_use` field on `CertIdentity`, populated by `parse_identity()`
  from the matched provider. Informational only — `parse_identity()`
  does not reject a cert based on this value; callers that need to
  enforce a use must check the field themselves or pass a constrained
  `ProviderRegistry`.

### Fixed

- `parse_identity` no longer falls back to "the last registered provider"
  when both OID and heuristic matching fail.  That fallback was
  registration-order-dependent and silently mislabeled certs from
  unrecognized issuers.  When neither match succeeds, `credential_type`
  is now `"UNKNOWN"`, regardless of how many providers are registered.

## [0.3.4] - 2026-04-21

### Security

- Bump `cryptography` minimum from `>=44.0` to `>=46.0.7` to resolve
  CVE-2026-26007 (ECDH small-subgroup key leakage), CVE-2026-34073
  (DNS name constraint bypass), and CVE-2026-39892 (buffer overflow on
  non-contiguous buffers).

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
