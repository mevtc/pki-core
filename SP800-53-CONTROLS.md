# NIST SP 800-53 Rev 5 Controls Mapping

This document maps NIST SP 800-53 Rev 5 security controls to their
implementation evidence across the pki ecosystem:

- **pki-core** — generic X.509 certificate utilities
- **pki-federal** — DoD CAC / Federal PIV / ECA provider pack
- **fpki-verify-milter** — S/MIME signature verification milter
- **smartcard-auth** — FastAPI smartcard authentication package

This mapping covers controls relevant to a PKI-based authentication
subsystem. Controls that apply to the hosting infrastructure (network,
physical, personnel) are out of scope.

---

## IA — Identification and Authentication

### IA-2: Identification and Authentication (Organizational Users)

| Requirement | Implementation | Evidence |
|---|---|---|
| Uniquely identify and authenticate users | smartcard-auth extracts a unique `primary_id` from the certificate (EDIPI, UUID, or DN) and maps it to an LLDAP user account | `dependencies.py:_authenticate_smartcard()` |
| | pki-federal `primary_id_selector` chooses the strongest available identifier per credential type | `selectors.py`, `providers.py` |

### IA-2(1): Multi-factor Authentication to Privileged Accounts

| Requirement | Implementation | Evidence |
|---|---|---|
| MFA for privileged accounts | PIV/CAC authentication is inherently MFA: something you have (smartcard with private key) + something you know (PIN to unlock card). The TLS handshake proves possession; the card enforces PIN entry | nginx `ssl_verify_client` + card middleware |
| | pki-federal sets `min_aal=3` on CAC and PIV providers, confirming AAL3 (hardware MFA) | `providers.py:CAC_PROVIDER`, `PIV_PROVIDER` |
| | smartcard-auth admin access requires LLDAP group membership in addition to certificate authentication | `dependencies.py:require_admin()` |

### IA-2(2): Multi-factor Authentication to Non-privileged Accounts

| Requirement | Implementation | Evidence |
|---|---|---|
| MFA for non-privileged accounts | Same PIV/CAC MFA mechanism applies to all smartcard-authenticated users, not just privileged accounts | smartcard-auth enrollment workflow |

### IA-2(6): Access to Accounts — Separate Device

| Requirement | Implementation | Evidence |
|---|---|---|
| One factor provided by a separate device | The PIV/CAC smartcard is a separate physical device from the workstation. The private key never leaves the card — cryptographic operations happen on-card | FIPS 201-3 §4.2.2 (card architecture) |

### IA-2(12): Acceptance of PIV Credentials

| Requirement | Implementation | Evidence |
|---|---|---|
| Accept and verify PIV credentials per FIPS 201 | pki-core `verify_chain()` validates the certificate chain to the Federal Common Policy CA | `validation.py:verify_chain()` |
| | pki-federal matches certificate policy OIDs (`id-fpki-common-authentication`, `id-fpki-common-derived-pivAuth`) to identify PIV credentials | `oids.py:FPKI_PIV_AUTH_OIDS` |
| | pki-core `check_algorithms()` with `SP800_78_ALGORITHM_POLICY` enforces SP 800-78 algorithm requirements | `algorithms.py`, `pki-federal/algorithms.py` |
| | pki-core CRL + OCSP revocation checking | `revocation.py:CRL`, `OCSP` |
| | pki-core extracts FASC-N and card UUID from SAN per FIPS 201-3 §4.2.4 | `certificate.py:extract_san_fascn()`, `extract_san_uuid()` |

### IA-5: Authenticator Management

| Requirement | Implementation | Evidence |
|---|---|---|
| Manage authenticator lifecycle | pki-core checks certificate validity period (`is_expired`, `is_not_yet_valid`) | `certificate.py` |
| Revocation of compromised authenticators | CRL checking with stale-while-revalidate cache; OCSP as fallback. Federal CRLConfig enforces 18-hour max age per FIPS 201-3 §2.9.1 | `crl.py`, `revocation.py`, `pki-federal/crl.py` |
| | smartcard-auth admin can remove users from LLDAP | `routers/admin.py` |

### IA-5(2): Public Key-Based Authentication

| Requirement | Implementation | Evidence |
|---|---|---|
| Validate certificates by constructing a path to a trust anchor | pki-core `verify_chain()` uses `cryptography`'s RFC 5280 path validator | `validation.py:verify_chain()` |
| Check certificate revocation status | Pluggable `RevocationCheck` strategies: `CRL` (cached HTTP fetch) and `OCSP` (live AIA query) | `revocation.py` |
| Map authenticated identity to an account | smartcard-auth maps `primary_id` to LLDAP UID for user lookup | `dependencies.py:_authenticate_smartcard()` |
| Enforce authorized access to private key | TLS terminator (nginx/ALB) performs the challenge-response. The private key never leaves the PIV card | nginx `ssl_verify_client` |

### IA-8: Identification and Authentication (Non-organizational Users)

| Requirement | Implementation | Evidence |
|---|---|---|
| Identify and authenticate non-organizational users | pki-federal `ECA_PROVIDER` handles External Certification Authority certificates issued to contractors | `providers.py:ECA_PROVIDER` |
| | ECA OIDs (`2.16.840.1.101.3.2.1.12.*`) are matched and identity extracted via `_parse_eca_human()` | `oids.py:ECA_AUTH_OIDS`, `cn_parsers.py` |
| | pki-federal `min_aal=2` for ECA (lower than CAC/PIV AAL3 since ECA may be software-based) | `providers.py:ECA_PROVIDER` |

### IA-8(1): Acceptance of PIV Credentials from Other Agencies

| Requirement | Implementation | Evidence |
|---|---|---|
| Accept PIV credentials from other agencies | Trust store includes FPKI Common Policy CA and bridge CA certificates, enabling cross-agency trust | `pki-federal/trust_store.py`, `providers.py:PIV_PROVIDER.trust_store_sources` |
| | pki-core `build_ca_bundle_for_providers()` fetches CA certificates from repo.fpki.gov | `trust_store.py` |

---

## SC — System and Communications Protection

### SC-12: Cryptographic Key Establishment and Management

| Requirement | Implementation | Evidence |
|---|---|---|
| Establish and manage cryptographic keys | Trust store management: pki-core downloads, merges, and deduplicates CA bundles from provider-defined sources (DISA, FPKI) | `trust_store.py:build_ca_bundle_for_providers()` |
| | CRL cache uses secure file permissions (0o700 directory, 0o600 files) | `crl.py:get_crl()`, `refresh_crl()` |

### SC-13: Cryptographic Protection

| Requirement | Implementation | Evidence |
|---|---|---|
| Use FIPS-validated cryptography | All cryptographic operations delegated to the `cryptography` library (OpenSSL backend). Deployments must use a FIPS 140-validated OpenSSL build | README Security sections |
| | fpki-verify-milter `require_fips` config option verifies FIPS provider at startup | `main.py` |
| | `SP800_78_ALGORITHM_POLICY` enforces approved algorithms at the application layer | `pki-federal/algorithms.py` |

### SC-17: Public Key Infrastructure Certificates

| Requirement | Implementation | Evidence |
|---|---|---|
| Issue/obtain certificates under approved policy | pki-federal defines policy OID registries for DoD, FPKI, and ECA aligned with their governing certificate policies | `oids.py` |
| Certificate validation | RFC 5280 chain validation, expiration, revocation | `validation.py:validate_certificate()` |
| Trust hierarchy management | Trust store sources point to authoritative CA bundle locations (DISA, repo.fpki.gov) | `providers.py` trust_store_sources |

### SC-23: Session Authenticity

| Requirement | Implementation | Evidence |
|---|---|---|
| Protect session authenticity | smartcard-auth uses `itsdangerous` for signed session cookies with configurable timeout | `config.py:SESSION_SECRET`, `SESSION_TIMEOUT` |
| | Runtime warning emitted if default insecure session secret is used | `config.py` |
| | mTLS provides mutual authentication at the transport layer | nginx `ssl_verify_client` |

---

## SA — System and Services Acquisition

### SA-11: Developer Testing and Evaluation

| Requirement | Implementation | Evidence |
|---|---|---|
| Security assessment plan | Automated CI pipelines run on every push and merge request across all four projects | `.gitlab-ci.yml`, `.github/workflows/ci.yml` |
| Unit and integration testing | 281 unit tests across the ecosystem | `tests/` directories |
| Fuzz testing | 232 Hypothesis property-based fuzz tests generating millions of random inputs per run | `tests/test_fuzz_*.py` |
| Verifiable flaw remediation | Pre-commit hooks (ruff, mypy) prevent introduction of known defect patterns. pip-audit checks dependency vulnerabilities | `.pre-commit-config.yaml`, CI pipelines |

### SA-11(1): Static Code Analysis

| Requirement | Implementation | Evidence |
|---|---|---|
| Static analysis tools | **ruff** — pycodestyle, pyflakes, isort, pyupgrade, flake8-bugbear, flake8-simplify | `pyproject.toml [tool.ruff]` |
| | **mypy** — static type checking | `pyproject.toml [tool.mypy]`, pre-commit hooks |
| | **bandit** — security-focused static analysis | `pyproject.toml [tool.bandit]`, CI pipelines |
| Document results | All suppressions documented with justifications in SECURITY.md | `SECURITY.md` |

### SA-11(5): Penetration Testing

| Requirement | Implementation | Evidence |
|---|---|---|
| Penetration testing | Penetration testing applies to the **deployed application**, not to these libraries. The libraries do not expose network services or user interfaces — they are consumed by applications that do | |
| Input boundary testing (library equivalent) | Hypothesis fuzz testing with adversarial inputs: arbitrary bytes to certificate parsers, injection payloads to header sanitization, malformed CRLs, random OID sets. Found and fixed a header injection vulnerability | `tests/test_fuzz_*.py`, CHANGELOG |

### SA-11(8): Dynamic Code Analysis

| Requirement | Implementation | Evidence |
|---|---|---|
| Dynamic code analysis | Hypothesis fuzz tests execute code with millions of random inputs, detecting crashes, assertion violations, and postcondition failures | `tests/test_fuzz_*.py` |
| | Fuzz testing discovered 2 bugs: header injection in fpki-verify-milter `serial` field, non-dict entries in smartcard-auth audit log | CHANGELOG entries |

---

## AU — Audit and Accountability

### AU-2: Event Logging

| Requirement | Implementation | Evidence |
|---|---|---|
| Identify and log security-relevant events | smartcard-auth logs: authentication success/failure, enrollment requests, admin actions (approve/deny/remove), invalid certificates, unknown users | `audit.py` |

### AU-3: Content of Audit Records

| Requirement | Implementation | Evidence |
|---|---|---|
| Records contain who, what, when, where, outcome | Structured JSONL with: `timestamp`, `event_type`, `primary_id`, `credential_type`, `cert_serial`, `source_ip`, `detail` | `audit.py:_log_event()` |

### AU-6: Audit Record Review, Analysis, and Reporting

| Requirement | Implementation | Evidence |
|---|---|---|
| Review and analyze audit records | smartcard-auth admin dashboard provides paginated audit log viewer | `routers/admin.py:GET /admin/audit` |

---

## SI — System and Information Integrity

### SI-2: Flaw Remediation

| Requirement | Implementation | Evidence |
|---|---|---|
| Identify and correct flaws | pip-audit scans dependencies for known vulnerabilities in CI | CI pipelines |
| | Dependabot / GitLab dependency scanning for upstream advisories | `.github/`, `.gitlab-ci.yml` |

### SI-7: Software, Firmware, and Information Integrity

| Requirement | Implementation | Evidence |
|---|---|---|
| Detect unauthorized changes | CRL signature verification ensures CRLs are authentic and untampered | `crl.py:verify_crl()` |
| | CA bundle integrity: trust store sources are HTTPS-only, with size limits (max_crl_bytes, 50 MB trust store limit) | `crl.py`, `trust_store.py` |
| Software integrity | **Partial gap** — no release signing (GPG/Sigstore) for published packages | |

### SI-10: Information Input Validation

| Requirement | Implementation | Evidence |
|---|---|---|
| Validate information inputs | Certificate parsing validates PEM/DER format with structured error handling (`CertificateError`) | `certificate.py:load_certificate()` |
| | fpki-verify-milter sanitizes all header values to prevent injection | `verify.py:_sanitize_header_value()` |
| | Message size limit (50 MB) prevents resource exhaustion | `milter.py:MAX_MESSAGE_BYTES` |
| | CRL size limit (`max_crl_bytes`) prevents oversized CRL attacks | `crl.py:CRLConfig.max_crl_bytes` |
| | AlgorithmPolicy rejects certificates with non-approved algorithms | `algorithms.py:check_algorithms()` |

---

## SR — Supply Chain Risk Management

### SR-4: Provenance

| Requirement | Implementation | Evidence |
|---|---|---|
| Document and maintain provenance | CycloneDX SBOMs generated in CI on every pipeline run, listing all direct and transitive dependencies with versions | CI pipelines (`cyclonedx-bom`) |
| | Git history provides full change provenance | Git repositories |

---

## CM — Configuration Management

### CM-7: Least Functionality

| Requirement | Implementation | Evidence |
|---|---|---|
| Provide only essential capabilities | Minimal dependency sets — each project depends only on what it needs | `pyproject.toml` dependencies |
| | pki-core has no web framework, no database, no network server — it is a pure library | `pyproject.toml` |
| | HTTPS-only enforcement for trust store and CRL downloads | `trust_store.py`, `crl.py` |

### CM-8: System Component Inventory

| Requirement | Implementation | Evidence |
|---|---|---|
| Maintain component inventory | CycloneDX SBOMs provide machine-readable dependency inventories | CI artifacts (`sbom.cdx.json`) |
| | `pyproject.toml` declares all direct dependencies with version constraints | `pyproject.toml` |

---

## Summary

### Controls fully addressed

IA-2, IA-2(1), IA-2(2), IA-2(6), IA-2(12), IA-5, IA-5(2), IA-8, IA-8(1),
SC-12, SC-13, SC-17, SC-23, SA-11, SA-11(1), SA-11(8), AU-2, AU-3, AU-6,
SI-2, SI-10, SR-4, CM-7, CM-8

### Controls partially addressed

| Control | Gap |
|---|---|
| SI-7 | No release signing — packages are published unsigned |

### Controls addressed at application level

These controls are the responsibility of the application that deploys
these libraries, not the libraries themselves.

| Control | Notes |
|---|---|
| SA-11(5) | Penetration testing applies to the deployed application, not libraries. These libraries provide the security primitives (input validation, chain validation, revocation) that the application's penetration test exercises. Fuzz testing provides the library-level equivalent of input boundary testing. |
| Privacy (PIA) | pki-core and pki-federal process PII (certificate fields, names, identifiers) but do not collect, store, or transmit it — they parse it from certificates and return it to the caller. Privacy Impact Assessments apply to the application that stores, logs, or displays that data. smartcard-auth is closer to an application in this regard (it stores enrollment requests and writes audit logs containing PII) and should be covered by the deploying application's PIA. |
