"""Primary ID selector functions for AuthProvider.primary_id_selector.

Each function matches Callable[[CertIdentity], str] and can be used
directly as AuthProvider.primary_id_selector.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .identity import CertIdentity


def select_edipi_first(identity: CertIdentity) -> str:
    """EDIPI > UUID > FASC-N > DN."""
    if identity.edipi:
        return f"edipi:{identity.edipi}"
    if identity.piv_uuid:
        return f"uuid:{identity.piv_uuid}"
    if identity.fascn:
        return f"fascn:{identity.fascn}"
    return f"dn:{identity.subject_dn}"


def select_uuid_first(identity: CertIdentity) -> str:
    """UUID > FASC-N > EDIPI > DN."""
    if identity.piv_uuid:
        return f"uuid:{identity.piv_uuid}"
    if identity.fascn:
        return f"fascn:{identity.fascn}"
    if identity.edipi:
        return f"edipi:{identity.edipi}"
    return f"dn:{identity.subject_dn}"


def select_email_first(identity: CertIdentity) -> str:
    """Email > DN."""
    if identity.email:
        return f"email:{identity.email}"
    return f"dn:{identity.subject_dn}"
