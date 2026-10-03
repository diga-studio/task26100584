"""Attachment inspection and neutralization on top of the parsed tree."""

from __future__ import annotations

import base64
import hashlib
import quopri
from typing import Dict, List, Optional, Tuple

from ._parse import (
    Part,
    content_type,
    decode_transfer,
    parse_message,
    transfer_encoding,
)

Path = Tuple[int, ...]
Edit = Tuple[int, int, bytes]  # (start, end, replacement) in buffer coords

_PLACEHOLDER_HEADERS = (b"Content-Type: text/plain\r\n"
                        b"Content-Transfer-Encoding: 7bit\r\n")
_PLACEHOLDER_BODY = b"Attachment removed"


def _is_multipart(part: Part) -> bool:
    ctype, _ = content_type(part)
    return ctype.startswith(b"multipart/") and bool(part.children)


def _is_rfc822(part: Part) -> bool:
    ctype, _ = content_type(part)
    return ctype == b"message/rfc822" and part.decoded_body is not None


def _is_attachment(part: Part) -> bool:
    disp = part.header("content-disposition")
    if disp is None:
        return False
    token = disp.split(b";", 1)[0].strip(b" \t").lower()
    return token in (b"attachment", b"inline")


def _leaf_payload(part: Part, buf: bytes) -> bytes:
    raw = buf[part.body_span[0]:part.body_span[1]]
    return decode_transfer(raw, transfer_encoding(part))


def _walk(part: Part, buf: bytes, path: Path, out: Dict[Path, str]) -> None:
    if _is_multipart(part):
        for i, child in enumerate(part.children):
            _walk(child, buf, path + (i,), out)
    elif _is_rfc822(part):
        _walk(part.children[0], part.decoded_body, path + (0,), out)
    elif _is_attachment(part):
        digest = hashlib.sha256(_leaf_payload(part, buf)).hexdigest()
        out[path] = digest


def collect_attachments(data: bytes) -> Dict[Path, str]:
    """Return {path: sha256-hex} for every attachment leaf in the message."""
    out: Dict[Path, str] = {}
    _walk(parse_message(data), data, (), out)
    return out


def _placeholder(part: Part, buf: bytes) -> bytes:
    """Replacement bytes for a blocked leaf: keep non-Content-* headers."""
    chunks: List[bytes] = []
    inserted = False
    for h in part.headers:
        if h.name.startswith("content-"):
            if not inserted:
                chunks.append(_PLACEHOLDER_HEADERS)
                inserted = True
        else:
            chunks.append(buf[h.span[0]:h.span[1]])
    if not inserted:
        chunks.insert(0, _PLACEHOLDER_HEADERS)
    return b"".join(chunks) + b"\r\n" + _PLACEHOLDER_BODY


def _encode_transfer(data: bytes, encoding: str) -> bytes:
    if encoding == "base64":
        return base64.encodebytes(data).replace(b"\n", b"\r\n")
    if encoding == "quoted-printable":
        return quopri.encodestring(data)
    return data


def _apply_edits(buf: bytes, edits: List[Edit]) -> bytes:
    out = bytearray()
    pos = 0
    for start, end, repl in sorted(edits):
        out += buf[pos:start]
        out += repl
        pos = end
    out += buf[pos:]
    return bytes(out)


def _process(part: Part, buf: bytes, path: Path, blocked: frozenset
             ) -> Tuple[List[Edit], List[Path]]:
    """Collect edits (in buf coordinates) and replaced paths for a subtree."""
    if _is_multipart(part):
        edits: List[Edit] = []
        replaced: List[Path] = []
        for i, child in enumerate(part.children):
            e, r = _process(child, buf, path + (i,), blocked)
            edits.extend(e)
            replaced.extend(r)
        return edits, replaced
    if _is_rfc822(part):
        inner_edits, replaced = _process(
            part.children[0], part.decoded_body, path + (0,), blocked)
        if not inner_edits:
            return [], []
        new_decoded = _apply_edits(part.decoded_body, inner_edits)
        encoded = _encode_transfer(new_decoded, transfer_encoding(part))
        return [(part.body_span[0], part.body_span[1], encoded)], replaced
    if _is_attachment(part):
        digest = hashlib.sha256(_leaf_payload(part, buf)).hexdigest()
        if digest in blocked:
            return ([(part.header_span[0], part.body_span[1],
                      _placeholder(part, buf))], [path])
    return [], []


def neutralize_message(data: bytes, blocked_hashes: frozenset
                       ) -> Tuple[bytes, List[Path]]:
    """Return (possibly rewritten bytes, list of replaced paths)."""
    tree = parse_message(data)
    edits, replaced = _process(tree, data, (), blocked_hashes)
    if not edits:
        return data, []
    return _apply_edits(data, edits), replaced
