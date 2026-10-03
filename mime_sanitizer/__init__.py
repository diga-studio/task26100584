"""Offline MIME attachment sanitizer for delivered raw message bytes."""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

from ._sanitize import collect_attachments, neutralize_message

Path = Tuple[int, ...]

__all__ = ["inspect", "neutralize", "Path"]


def inspect(raw: bytes) -> Dict[Path, str]:
    """Return {attachment path: sha256 hex of transfer-decoded payload}."""
    return collect_attachments(raw)


def neutralize(raw: bytes, blocked_hashes: Iterable[str]) -> Tuple[bytes, List[Path]]:
    """Replace blocked attachments with a text/plain placeholder.

    Returns (sanitized bytes, list of replaced paths).  With no hits the
    returned bytes are identical to the input.
    """
    return neutralize_message(raw, frozenset(h.lower() for h in blocked_hashes))
