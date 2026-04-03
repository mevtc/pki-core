"""Authentication provider definitions and registry.

Each AuthProvider encapsulates the certificate-matching OIDs, CN parsing
callable, primary-ID selection callable, heuristic detection rules, and
trust-store source URLs for a single credential ecosystem.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .identity import CertIdentity


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


@dataclass
class ProviderRegistry:
    """Ordered collection of active authentication providers.

    Providers are matched in insertion order: the first provider whose
    auth_oids intersect the certificate's policy OIDs wins.
    """

    _providers: dict[str, AuthProvider] = field(default_factory=dict)

    def register(self, provider: AuthProvider) -> None:
        """Add or replace a provider.

        Validates regex patterns in heuristic rules at registration time.
        Pattern complexity is the caller's responsibility.
        """
        for rule in provider.heuristics:
            if rule.is_regex:
                try:
                    re.compile(rule.pattern)
                except re.error as e:
                    raise ValueError(
                        f"Invalid regex in heuristic for provider {provider.name!r}: {e}"
                    ) from e
        self._providers[provider.name] = provider

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
        """Return the first provider whose auth_oids intersect policy_oids."""
        for provider in self._providers.values():
            if policy_oids & provider.auth_oids:
                return provider
        return None

    def match_heuristic(
        self,
        cn: str | None,
        org: str | None,
        ou: str | None,
    ) -> AuthProvider | None:
        """Return the first provider matched by heuristic rules."""
        for provider in self._providers.values():
            for rule in provider.heuristics:
                value = {"cn": cn, "org": org, "ou": ou}.get(rule.field)
                if value is None:
                    continue
                if rule.is_regex:
                    if re.match(rule.pattern, value):
                        return provider
                else:
                    if rule.pattern in value.lower():
                        return provider
        return None

    def __len__(self) -> int:
        """Return the number of registered providers."""
        return len(self._providers)
