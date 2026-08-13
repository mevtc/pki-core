# 1. Revocation checking is fail-open by default

## Status

Accepted

## Context

pki-core's revocation pipeline (`RevocationPolicy`, `CRLCheck`, `OCSPCheck`
in `revocation.py`, and `check_revocation`/`verify_crl` in `crl.py`) is used
by a wide range of callers, from quick scripts that just want to parse and
sanity-check a certificate to production services (pki-federal,
fpki-verify-milter, smartcard-auth, authn-smartcard) that make trust
decisions with real consequences.

Full, defensible revocation checking requires the caller to operate CRL/OCSP
infrastructure correctly: supplying the issuing CA's certificate(s) so
fetched CRLs and OCSP responses can be cryptographically authenticated,
deciding what to do when no revocation source is configured on a
certificate, and deciding how to handle transient unavailability. Many
callers of this library do not want or need that — they want
`validate_certificate(cert)` to work with zero configuration and return a
reasonable answer for well-formed, non-revoked certificates.

To serve that "quick parse and validate" use case without forcing every
caller to configure a CA bundle up front, the library was built so that
revocation checking degrades gracefully in the absence of configuration,
rather than refusing to proceed. This tradeoff was made implicitly, in the
defaults chosen for `RevocationPolicy` and in how missing CRL distribution
points are handled — not through an explicit, reviewed design decision. This
ADR records that tradeoff explicitly so it is a known, documented property
of the library rather than a discovered surprise.

## Decision

pki-core's revocation checking defaults are **fail-open** in two specific,
concrete ways:

1. **CRL signature verification is skipped unless `issuer_certs` is
   supplied.** `RevocationPolicy.issuer_certs` defaults to `None`
   (`revocation.py:194`). When `None`, `verify_crl()` is never called
   (`crl.py:151-194`), so a fetched CRL's signature, issuer binding, and
   `nextUpdate` freshness are never checked — the CRL's revocation list is
   trusted as-is. `check_revocation()`'s docstring already states this is
   "backward compatible" behavior; this ADR makes explicit that it is also
   a security tradeoff, not just a compatibility nicety.

2. **A certificate with no CRL distribution point is reported as GOOD
   ("not revoked"), not UNAVAILABLE ("unknown").** `crl.py:171-177` and
   `revocation.py:97-99` log a warning and return normally rather than
   signaling that revocation status could not be determined. Because GOOD
   short-circuits the `RevocationPolicy` pipeline, this also means
   `strict=True` (the fail-closed default) is never consulted for such
   certificates — there is nothing for it to fail closed on.

Neither behavior is a bug in isolation: both are documented in code
comments and docstrings as intentional, backward-compatible defaults. The
issue is that their *security* consequences — especially in combination
with `CertificatePolicy`'s own `check_chain=False` default — were not
previously stated anywhere a consumer of the library would see them before
relying on the defaults.

## Consequences

**Risks of the current defaults**, tracked individually in the
`## Security` section of `TODO.md`:

- Calling `validate_certificate(cert)` with all defaults performs no chain
  validation (`check_chain=False`) and, if revocation checking is enabled,
  trusts an unauthenticated CRL fetched from a URL the presented
  certificate itself supplies — an attacker who controls the certificate
  effectively controls the answer to "is this certificate revoked."
- A certificate that omits a CRL distribution point (or whose CRL DP is
  unreachable in a way the caller didn't anticipate) is silently treated
  as not revoked, with no way for a `strict=True` caller to distinguish
  "confirmed good" from "we couldn't check."
- Related gaps compound this: CRLs are not bound to the certificate's
  actual issuer, `verify_crl()`'s failure result is discarded in
  non-strict mode, OCSP responses have no freshness or replay protection,
  and revocation URL fetches are not hardened against SSRF. See `TODO.md`
  for the full itemized list.

**What this ADR recommends for security-sensitive callers** (pki-federal,
fpki-verify-milter, smartcard-auth, authn-smartcard, and any other
downstream consumer making authentication or authorization decisions):

- Always construct `RevocationPolicy(issuer_certs=...)` explicitly with the
  relevant CA certificates loaded — never rely on the `issuer_certs=None`
  default.
- Always set `CertificatePolicy(check_chain=True)` with an explicit trust
  anchor; do not rely on the default.
- Treat `strict=True` (already the default) as mandatory, and additionally
  have an explicit policy decision for "no revocation source was available
  on this certificate" — do not assume GOOD-with-no-CRL-DP means the same
  thing as GOOD-with-a-verified-CRL.
- Track the SSRF and OCSP-freshness items in `TODO.md` before exposing
  revocation checking to attacker-supplied certificates in an
  internet-facing service.

**What this ADR does not do:** it does not change any default. The
zero-configuration fail-open behavior remains the out-of-the-box behavior
for callers who have not opted into stricter configuration, because that is
judged to be the right tradeoff for the library's broader (non-security-
critical) audience. Changing these defaults is tracked separately in
`TODO.md` ("Document that `check_chain=True` is required for
security-sensitive use" already proposes reconsidering the `check_chain`
default in a future major version; the same reconsideration should extend
to `RevocationPolicy.issuer_certs` and the no-CRL-DP-means-GOOD behavior if
this library's target audience shifts toward security-critical use by
default).
