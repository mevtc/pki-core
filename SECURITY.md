# Security Policy

For the full incident response process, severity classification, response
timelines, and disclosure policy, see
[oss.mevtc.com/security](https://oss.mevtc.com/security).

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Email **info.security@mevtc.com**.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |
| 0.2.x   | No        |
| 0.1.x   | No        |

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
