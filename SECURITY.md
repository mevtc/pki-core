# Security Policy

For the full incident response process, severity classification, response
timelines, and disclosure policy, see
[oss.mevtc.com/security](https://oss.mevtc.com/security).

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Email **info.security@mevtc.com**.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.5.x   | Yes       |
| 0.4.x   | No        |
| 0.3.x   | No        |
| 0.2.x   | No        |
| 0.1.x   | No        |

0.4.x was tagged internally but never published to PyPI; it is listed only
so the sequence is unambiguous. 0.3.4 was the previous release on PyPI —
upgrade to 0.5.x to remain on a supported version.

## Security Boundaries

pki-core performs cryptographic and structural certificate operations, but
several security-relevant checks are **opt-in** rather than on-by-default,
in order to keep zero-configuration parsing and validation usable. Calling
applications with security-sensitive requirements must explicitly configure
or independently verify the following:

- **Chain validation is opt-in.** `CertificatePolicy` defaults to
  `check_chain=False`. Without `check_chain=True` and a trust anchor,
  `validate_certificate()` performs no trust-path enforcement at all.

- **CRL signature verification is opt-in.** `RevocationPolicy` defaults to
  `issuer_certs=None`, which skips CRL signature verification entirely.
  Pass `issuer_certs` explicitly to have fetched CRLs authenticated against
  known CA certificates before being trusted.

- **A missing CRL distribution point is treated as "not revoked," not
  "unknown."** A certificate with no CRL DP currently reports revocation
  status as GOOD rather than UNAVAILABLE. This also means `strict=True`
  fail-closed behavior is never reached for such certificates.

- **OCSP responses have no freshness or replay protection.** Responses are
  not checked against `this_update`/`next_update`, and requests do not
  include a nonce. A captured GOOD response can be replayed after the
  underlying certificate is revoked.

- **Revocation and trust-store URL fetches are not SSRF-hardened.** CRL,
  OCSP, and trust-store download requests follow redirects and do not
  block private-IP, link-local, or cloud metadata-endpoint targets, and
  CRL/OCSP URLs are taken directly from the certificate under validation.
  Applications embedding this library in an internet-facing service should
  apply their own egress controls (network policy, URL allow-listing, or a
  proxy that blocks internal address ranges) around these fetches.

See the `## Security` section of `TODO.md` for the full list of tracked
issues and [`docs/adr/0001-revocation-fail-open-by-default.md`](docs/adr/0001-revocation-fail-open-by-default.md)
for the rationale behind the current fail-open revocation defaults.

## Security Testing

This project uses [Hypothesis](https://hypothesis.readthedocs.io/) for
property-based fuzz testing. Fuzz tests run in CI on every push and merge
request, with higher iteration counts on nightly schedules.

Fuzz test coverage includes certificate parsing with arbitrary bytes, CRL
parsing, algorithm policy enforcement, revocation pipeline ordering, identity
extraction, and provider matching.

## Static Analysis Suppressions

The following static analysis checks are suppressed project-wide. Each
suppression is documented here with its justification.

### Bandit

Configured in `pyproject.toml` under `[tool.bandit]`.

| Rule | Description | Justification |
|------|-------------|---------------|
| B101 | `assert` used outside tests | Asserts are used only in test code. Bandit scans `src/` only (`exclude_dirs = ["tests"]`), but the suppression avoids false positives from shared fixtures. |
| B110 | `try`/`except`/`pass` (bare exception handling) | Used in certificate parsing fallback chains (try PEM, fall back to DER). The `pass` is intentional — failure of one format triggers the next. |

### Ruff

Configured in `pyproject.toml` under `[tool.ruff.lint]`.

| Rule | Description | Justification |
|------|-------------|---------------|
| E501 | Line too long | Line length is enforced by `ruff format`, not the linter. Suppressing the lint rule avoids conflicts between the formatter and linter. |

### Inline Type Suppressions

The `cryptography` library's type stubs do not fully cover the `x509`
extension value types. The following `# type: ignore[attr-defined]` comments
suppress mypy errors where the runtime API is correct but the type stubs
are incomplete:

| File | Line | Reason |
|------|------|--------|
| `certificate.py` | `ext.value` iteration | `CertificatePolicies` and `SubjectAlternativeName` are iterable at runtime but typed as `ExtensionType` |
| `crl.py` | `crl.is_signature_valid()` | Argument type is broader at runtime than the stub declares |
| `revocation.py` | `aia.value` iteration | `AuthorityInformationAccess` is iterable at runtime |
