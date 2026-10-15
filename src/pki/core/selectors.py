"""Primary ID selector functions for AuthProvider.primary_id_selector.

Each function matches Callable[[CertIdentity], str] and can be used
directly as AuthProvider.primary_id_selector.  The result is scoped by
``parse_identity()``, which prefixes it with the provider (and trust domain),
so selectors return only the identifier within that scope.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .identity import CertIdentity


def scoped_dn(identity: CertIdentity) -> str:
    """Issuer + subject DN.  RFC 5280 makes a subject name unique only per issuer."""
    return f"dn:{identity.cert_issuer_dn};{identity.subject_dn}"


def select_edipi_first(identity: CertIdentity) -> str:
    """EDIPI > UUID > FASC-N > DN."""
    if identity.edipi:
        return f"edipi:{identity.edipi}"
    if identity.piv_uuid:
        return f"uuid:{identity.piv_uuid}"
    if identity.fascn:
        return f"fascn:{identity.fascn}"
    return scoped_dn(identity)


def select_uuid_first(identity: CertIdentity) -> str:
    """UUID > FASC-N > EDIPI > DN."""
    if identity.piv_uuid:
        return f"uuid:{identity.piv_uuid}"
    if identity.fascn:
        return f"fascn:{identity.fascn}"
    if identity.edipi:
        return f"edipi:{identity.edipi}"
    return scoped_dn(identity)


def select_email_first(identity: CertIdentity) -> str:
    """Email > DN."""
    if identity.email:
        return f"email:{identity.email}"
    return scoped_dn(identity)
