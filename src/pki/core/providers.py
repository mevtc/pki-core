"""Authentication provider definitions and registry.

Each AuthProvider encapsulates the certificate-matching OIDs, CN parsing
callable, primary-ID selection callable, heuristic detection rules, and
trust-store source URLs for a single credential ecosystem.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Flag, auto
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .identity import CertIdentity

logger = logging.getLogger(__name__)


class IntendedUse(Flag):
    """Capability flags declaring what a credential class is approved for.

    A provider may set multiple bits when a single policy genuinely
    permits multiple uses (e.g. FPKI common-hardware allows personal
    authentication and digital signature on the same cert).  Consumers
    enforce intent at the security boundary using set membership:

        if IntendedUse.PERSONAL_AUTH not in provider.intended_use:
            raise AuthError(...)

    New flags may be added without restructuring existing providers.

    ``CARD_AUTH`` is deliberately its own bit rather than a shade of
    ``PERSONAL_AUTH`` or ``NPE_AUTH``.  A card-authentication credential
    (PIV / PIV-I Card Authentication, ``id-PIV-cardAuth``) is neither: it
    is not a device, and it does not authenticate the holder.  Its private
    key requires no activation data, so — in the words of the DoD ECA CP —
    validating one "provides only proof of the physical presence of the
    smart card token.  It provides no proof of the identity of the
    individual in possession of the token."

    It therefore must never satisfy a ``PERSONAL_AUTH`` check: on a real
    card the card-authentication and personal-authentication certificates
    can carry the *same* subject identifier, so treating the former as the
    latter lets a PIN-less read authenticate as the cardholder.  Folding it
    into ``NPE_AUTH`` would be no better — it would then satisfy device
    authentication, which it is equally not approved for.
    """

    PERSONAL_AUTH = auto()  # Human signing in or signing as themselves
    NPE_AUTH = auto()  # Non-Person Entity (service/device) authentication
    OBJECT_SIGNING = auto()  # Content / code / document signing at scale
    ENCRYPTION = auto()  # Key transport / encipherment
    TIMESTAMPING = auto()  # Time-stamp authority signing
    CARD_AUTH = auto()  # Card/token presence only — see below


# Resolution order when a certificate's policy OIDs match providers of more
# than one intended use.  Least-privileged first: PERSONAL_AUTH is the most
# powerful classification a credential can receive, so it is reachable only
# when no narrower class also matched.
#
# CARD_AUTH leads because a card-authentication key needs no activation data —
# it proves the token is present and nothing about who holds it — and its OID
# is definitional for that. NPE_AUTH follows for the same reason: DoD CP v11
# requires every device certificate to assert an NPE OID, so its presence
# identifies a device no matter what else is asserted.
_USE_PRECEDENCE: tuple[IntendedUse, ...] = (
    IntendedUse.CARD_AUTH,
    IntendedUse.NPE_AUTH,
    IntendedUse.OBJECT_SIGNING,
    IntendedUse.TIMESTAMPING,
    IntendedUse.ENCRYPTION,
    IntendedUse.PERSONAL_AUTH,
)


@dataclass(frozen=True)
class HeuristicRule:
    """A single heuristic for guessing credential type from cert fields."""

    field: str  # "org", "cn", or "ou"
    pattern: str  # Substring (case-insensitive) or regex
    is_regex: bool = False


@dataclass(frozen=True)
class TrustStoreSource:
    """A CA certificate download source."""

    url: str
    format: str = "pkcs7_zip"  # "pkcs7_zip", "pkcs7_der", "der", "pem"
    label: str = ""


@dataclass(frozen=True)
class AuthProvider:
    """A credential ecosystem definition.

    Instances are immutable (frozen) so they can be safely shared across
    threads and used as dict values without defensive copies.
    """

    name: str
    display_name: str
    auth_oids: frozenset[str]
    cn_parser: Callable[[CertIdentity], None]
    primary_id_selector: Callable[[CertIdentity], str]
    heuristics: tuple[HeuristicRule, ...] = ()
    trust_store_sources: tuple[TrustStoreSource, ...] = ()
    email_signing_oids: frozenset[str] = frozenset()
    min_aal: int = 2
    controls: tuple[str, ...] = ()
    intended_use: IntendedUse = IntendedUse.PERSONAL_AUTH
    # Policy OIDs whose presence disqualifies this provider outright, whatever
    # else the certificate asserts.  Needed because a certificate may carry
    # OIDs from two use classes: DoD CP v11 lets a device certificate assert a
    # person OID alongside its mandatory NPE OID.  Least-privilege precedence
    # in match_oids() resolves that only when a provider for the narrower class
    # is registered — in a registry constrained to PERSONAL_AUTH there is none,
    # so the person provider must be able to rule *itself* out.
    disqualifying_oids: frozenset[str] = frozenset()


@dataclass
class ProviderRegistry:
    """Ordered collection of active authentication providers.

    Insertion order determines presentation (``names()``, ``all()``) and
    breaks ties between providers of the *same* intended use.  It does **not**
    decide between different use classes: when a certificate's policy OIDs
    match providers that disagree about ``intended_use``,
    :meth:`match_oids` resolves by least privilege rather than by
    registration order.  See that method for why.

    A registry may be constrained to a specific IntendedUse at
    construction time.  When constrained, register() refuses any
    provider whose intended_use does not include the constraint —
    making mis-composition a definition-time error rather than a
    runtime security boundary violation.
    """

    intended_use: IntendedUse | None = None
    _providers: dict[str, AuthProvider] = field(default_factory=dict)
    _compiled_patterns: dict[str, dict[str, re.Pattern]] = field(default_factory=dict, repr=False)

    def register(self, provider: AuthProvider) -> None:
        """Add or replace a provider.

        Validates and pre-compiles regex patterns in heuristic rules at
        registration time.  Pattern complexity is the caller's responsibility.

        If the registry was constructed with an intended_use constraint,
        the provider's intended_use must include all constrained bits.
        """
        if self.intended_use is not None and self.intended_use not in provider.intended_use:
            raise ValueError(
                f"Provider {provider.name!r} (intended_use={provider.intended_use!r}) "
                f"does not support {self.intended_use!r}; "
                f"this registry refuses providers missing the constrained bits"
            )
        compiled: dict[str, re.Pattern] = {}
        for rule in provider.heuristics:
            if rule.is_regex:
                try:
                    compiled[rule.pattern] = re.compile(rule.pattern)
                except re.error as e:
                    raise ValueError(
                        f"Invalid regex in heuristic for provider {provider.name!r}: {e}"
                    ) from e
        self._providers[provider.name] = provider
        self._compiled_patterns[provider.name] = compiled

    def get(self, name: str) -> AuthProvider | None:
        """Look up a provider by name."""
        return self._providers.get(name)

    def all(self) -> list[AuthProvider]:
        """Return all providers in registration order."""
        return list(self._providers.values())

    def names(self) -> list[str]:
        """Return provider names in registration order."""
        return list(self._providers.keys())

    def match_oids(self, policy_oids: set[str]) -> AuthProvider | None:
        """Return the provider matching ``policy_oids``, least-privileged first.

        A certificate may legitimately assert policy OIDs from more than one
        use class.  DoD CP v11 Section 1.2 is explicit: "All NPE certificates
        shall assert the appropriate Internal NPE or Medium NPE OID.  Medium
        NPE certificates **may also assert any Medium Software or Medium
        Hardware OID** if they meet the corresponding requirements."  So a
        device certificate can carry a person OID alongside its device OID.

        Returning the first registered match would let dict insertion order
        decide whether such a certificate is a person or a device — making
        registration order a security control.  Instead, when the matched
        providers disagree about ``intended_use``, the least-privileged class
        wins, per :data:`_USE_PRECEDENCE`.  The NPE or card-auth assertion is
        definitional: a person credential never carries one.

        When the matched providers disagree in a way the precedence list does
        not cover, this returns ``None`` rather than guessing — a valid
        credential rejected is recoverable, a device authenticated as a human
        is not.

        Args:
            policy_oids: Certificate policy OIDs from the certificate.

        Returns:
            The matching provider, or ``None`` if nothing matched or the match
            was ambiguous.
        """
        matches = [
            p
            for p in self._providers.values()
            if policy_oids & p.auth_oids and not (policy_oids & p.disqualifying_oids)
        ]
        if not matches:
            return None

        uses = {p.intended_use for p in matches}
        if len(uses) == 1:
            # Unambiguous: every match agrees on the use class, so registration
            # order is a presentation detail rather than a security decision.
            return matches[0]

        for use in _USE_PRECEDENCE:
            for provider in matches:
                if provider.intended_use is use:
                    logger.debug(
                        "Certificate policy OIDs matched %d use classes (%s); "
                        "resolved to %s by least-privilege precedence",
                        len(uses),
                        ", ".join(sorted(u.name or str(u) for u in uses)),
                        provider.name,
                    )
                    return provider

        logger.warning(
            "Certificate policy OIDs matched providers with conflicting "
            "intended_use (%s) and no precedence applies; refusing to classify",
            ", ".join(sorted(str(u) for u in uses)),
        )
        return None

    def match_heuristic(
        self,
        cn: str | None,
        org: str | None,
        ou: str | None,
    ) -> AuthProvider | None:
        """Return the first provider matched by heuristic rules."""
        for provider in self._providers.values():
            compiled = self._compiled_patterns.get(provider.name, {})
            for rule in provider.heuristics:
                value = {"cn": cn, "org": org, "ou": ou}.get(rule.field)
                if value is None:
                    continue
                if rule.is_regex:
                    pat = compiled.get(rule.pattern)
                    if pat and pat.match(value):
                        return provider
                else:
                    if rule.pattern in value.lower():
                        return provider
        return None

    def __len__(self) -> int:
        """Return the number of registered providers."""
        return len(self._providers)
