# 2. A missing CRL distribution point means "unknown", not "not revoked"

## Status

Accepted (2026-10-14). Supersedes item 2 of ADR 0001.

## Context

ADR 0001 recorded that a certificate with no CRL distribution point was
reported GOOD: `check_revocation()` logged a warning and returned, and
`CRLCheck` turned that into GOOD. GOOD short-circuits the revocation
pipeline, so `RevocationPolicy.strict` -- the library's fail-closed control,
on by default -- was never consulted for such a certificate, and a strict
caller could not tell "confirmed not revoked" from "could not check".

ADR 0001 kept that default for the library's zero-configuration audience and
named the condition for revisiting it: the audience shifting toward
security-critical use. It has. Every consumer of this library now makes
authentication decisions with it -- pki-federal, authn-smartcard (which
revocation-checks every certificate in a validated chain), the enrollment
and milter services -- and none of them wants an unchecked certificate
treated as good. The gap was visible in practice: a demo deployment logged
"no CRL distribution points; skipping revocation check" on every login and
admitted the certificate at HIGH assurance.

## Decision

A certificate with no CRL distribution point has *unknown* revocation status.

- `CRLCheck` returns `UNAVAILABLE` for it, so the next strategy (e.g. OCSP
  from the AIA extension) is tried, and if none answers,
  `RevocationPolicy.strict` alone decides: strict (the default) fails
  closed, non-strict allows with a warning.
- `check_revocation()` follows its `CRLConfig.strict`: strict raises
  `CertificateError`, non-strict warns and returns.

Item 1 of ADR 0001 (CRL signatures verified only when `issuer_certs` is
given) is unchanged here; with `check_chain=True` it no longer applies,
because each CRL is verified against the issuer found in the chain.

## Consequences

- **Breaking** for strict callers whose certificates lack a CRL distribution
  point and who relied on them passing. DoD, FPKI and ECA certificates and
  their intermediates carry distribution points; private or test PKIs often
  do not, and must add them (or an OCSP responder with `checks=(CRL, OCSP)`),
  or opt out explicitly with `strict=False`.
- Roots are never revocation-checked, so self-signed anchors are unaffected.
- Test suites that build certificates must give them distribution points and
  serve CRLs; that also makes them exercise revocation instead of skipping it.
