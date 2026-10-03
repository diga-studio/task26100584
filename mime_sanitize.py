"""Offline MIME attachment sanitizer for delivered raw email bytes.

Only local SHA-256 blacklist matching is performed. No URL inspection,
no mail transport, no persistence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import quopri
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

Path = Tuple[int, ...]

PLACEHOLDER_BODY = b"Attachment removed"

_PLACEHOLDER_CONTENT_HEADERS: Tuple[Tuple[bytes, bytes], ...] = (
    (b"Content-Type", b"text/plain"),
    (b"Content-Transfer-Encoding", b"7bit"),
)

_CONTAINER_MULTIPART_PREFIX = "multipart/"
_MESSAGE_RFC822 = "message/rfc822"


@dataclass
class Header:
    """A single parsed header field (raw bytes preserved)."""

    name: bytes
    value: bytes
    raw: bytes


@dataclass
class Node:
    """Parsed MIME entity spanning raw[start:end] of its layer's bytes."""

    start: int
    end: int
    headers: List[Header] = field(default_factory=list)
    body_start: int = 0
    body_end: int = 0
    content_type: str = "text/plain"
    content_type_params: Dict[str, str] = field(default_factory=dict)
    transfer_encoding: str = "7bit"
    disposition: Optional[str] = None
    is_multipart: bool = False
    is_message_rfc822: bool = False
    children: List["Node"] = field(default_factory=list)

    @property
    def is_container(self) -> bool:
        return self.is_multipart or self.is_message_rfc822

    @property
    def is_attachment(self) -> bool:
        return (
            not self.is_container
            and self.disposition in ("attachment", "inline")
        )


def _split_header_block(raw: bytes, start: int, end: int) -> Tuple[int, int]:
    """Return (header_end, body_start) for the entity at raw[start:end].

    header_end is the end of the header-field region (the blank line is
    excluded); body_start is just past the blank CRLF line. If the entity
    has no headers, both equal the body start.
    """
    sep = raw.find(b"\r\n\r\n", start, end)
    if sep == -1:
        if raw[start:start + 2] == b"\r\n":
            return start, start + 2
        return start, start
    return sep, sep + 4


def _parse_headers(raw: bytes, start: int, end: int) -> List[Header]:
    """Parse header fields in raw[start:end]; unfolding continuation lines.

    The region must not include the terminating blank line.
    """
    headers: List[Header] = []
    pos = start
    cur_start: Optional[int] = None
    cur_end = start
    while pos < end:
        line_end = raw.find(b"\r\n", pos, end)
        if line_end == -1:
            line_end = end
            next_pos = end
        else:
            next_pos = line_end + 2
        is_continuation = pos < end and raw[pos:pos + 1] in (b" ", b"\t")
        if is_continuation and cur_start is not None:
            pass
        else:
            if cur_start is not None:
                headers.append(_make_header(raw[cur_start:cur_end]))
            cur_start = pos
        cur_end = line_end
        pos = next_pos
    if cur_start is not None and cur_start < end:
        headers.append(_make_header(raw[cur_start:cur_end]))
    return headers


def _make_header(raw_field: bytes) -> Header:
    first_line = raw_field.split(b"\r\n", 1)[0]
    name, _, value = first_line.partition(b":")
    unfolded = b" ".join(line.strip() for line in raw_field.split(b"\r\n"))
    value = unfolded.partition(b":")[2].strip()
    return Header(name=name.strip(), value=value, raw=raw_field)


def _decode_transfer(data: bytes, encoding: str) -> bytes:
    enc = encoding.lower()
    if enc == "base64":
        return binascii.a2b_base64(b"".join(data.split()))
    if enc == "quoted-printable":
        return quopri.decodestring(data)
    return data


def _encode_transfer(data: bytes, encoding: str) -> bytes:
    enc = encoding.lower()
    if enc == "base64":
        encoded = base64.b64encode(data)
        lines = [encoded[i:i + 76] for i in range(0, len(encoded), 76)]
        return b"\r\n".join(lines) + b"\r\n"
    if enc == "quoted-printable":
        return quopri.encodestring(data, quotetabs=True)
    return data


def _header_values(headers: List[Header], name: bytes) -> List[bytes]:
    lname = name.lower()
    return [h.value for h in headers if h.name.lower() == lname]


def _parse_type_and_params(value: bytes) -> Tuple[str, Dict[str, str]]:
    parts = value.split(b";")
    main = parts[0].strip().decode("ascii", "replace").lower()
    params: Dict[str, str] = {}
    for piece in parts[1:]:
        pname, _, pval = piece.partition(b"=")
        pname = pname.strip().decode("ascii", "replace").lower()
        pval = pval.strip()
        if len(pval) >= 2 and pval[:1] == b'"' and pval[-1:] == b'"':
            pval = pval[1:-1]
        if pname:
            params[pname] = pval.decode("ascii", "replace")
    return main, params


def _parse_node(raw: bytes, start: int, end: int) -> Node:
    header_end, body_start = _split_header_block(raw, start, end)
    headers = _parse_headers(raw, start, header_end)
    node = Node(start=start, end=end, headers=headers,
                body_start=body_start, body_end=end)

    ctype_values = _header_values(headers, b"content-type")
    if ctype_values:
        node.content_type, node.content_type_params = _parse_type_and_params(
            ctype_values[-1])

    cte_values = _header_values(headers, b"content-transfer-encoding")
    if cte_values:
        node.transfer_encoding = (
            cte_values[-1].strip().decode("ascii", "replace").lower())

    disp_values = _header_values(headers, b"content-disposition")
    if disp_values:
        node.disposition = (
            disp_values[-1].split(b";")[0].strip()
            .decode("ascii", "replace").lower())

    if node.content_type.startswith(_CONTAINER_MULTIPART_PREFIX):
        node.is_multipart = True
        _parse_multipart_children(raw, node)
    elif node.content_type == _MESSAGE_RFC822:
        node.is_message_rfc822 = True
        decoded = _decode_transfer(
            raw[node.body_start:node.body_end], node.transfer_encoding)
        child = _parse_node(decoded, 0, len(decoded))
        node.children.append(child)
    return node


def _parse_multipart_children(raw: bytes, node: Node) -> None:
    boundary = node.content_type_params.get("boundary", "")
    delimiter = b"--" + boundary.encode("ascii", "replace")
    closing = delimiter + b"--"
    lines: List[Tuple[int, int, bool]] = []
    pos = node.body_start
    while pos < node.body_end:
        line_end = raw.find(b"\r\n", pos, node.body_end)
        if line_end == -1:
            line_end = node.body_end
            next_pos = node.body_end
        else:
            next_pos = line_end + 2
        stripped = raw[pos:line_end].rstrip(b" \t")
        if stripped == delimiter or stripped == closing:
            lines.append((pos, next_pos, stripped == closing))
        pos = next_pos
    part_start: Optional[int] = None
    for line_start, line_end, is_closing in lines:
        if part_start is not None:
            node.children.append(
                _parse_node(raw, part_start, line_start - 2))
        part_start = None if is_closing else line_end


def _walk_attachments(
    raw: bytes, node: Node, path: Path
) -> List[Tuple[Path, str]]:
    if node.is_multipart:
        found: List[Tuple[Path, str]] = []
        for index, child in enumerate(node.children):
            found.extend(_walk_attachments(raw, child, path + (index,)))
        return found
    if node.is_message_rfc822:
        decoded = _decode_transfer(
            raw[node.body_start:node.body_end], node.transfer_encoding)
        return _walk_attachments(decoded, node.children[0], path + (0,))
    if node.is_attachment:
        payload = _decode_transfer(
            raw[node.body_start:node.body_end], node.transfer_encoding)
        return [(path, hashlib.sha256(payload).hexdigest())]
    return []


def _neutralize_node(
    raw: bytes, node: Node, path: Path, blocked: frozenset
) -> Tuple[bytes, List[Path]]:
    if node.is_multipart:
        replaced: List[Path] = []
        segments: List[Tuple[Node, bytes]] = []
        for index, child in enumerate(node.children):
            child_bytes, child_paths = _neutralize_node(
                raw, child, path + (index,), blocked)
            segments.append((child, child_bytes))
            replaced.extend(child_paths)
        if not replaced:
            return raw[node.start:node.end], replaced
        out = bytearray()
        cursor = node.start
        for child, child_bytes in segments:
            out += raw[cursor:child.start]
            out += child_bytes
            cursor = child.end
        out += raw[cursor:node.end]
        return bytes(out), replaced
    if node.is_message_rfc822:
        decoded = _decode_transfer(
            raw[node.body_start:node.body_end], node.transfer_encoding)
        child = node.children[0]
        child_bytes, replaced = _neutralize_node(
            decoded, child, path + (0,), blocked)
        if not replaced:
            return raw[node.start:node.end], replaced
        new_decoded = (
            decoded[:child.start] + child_bytes + decoded[child.end:])
        new_payload = _encode_transfer(new_decoded, node.transfer_encoding)
        return (raw[node.start:node.body_start] + new_payload
                + raw[node.body_end:node.end]), replaced
    if node.is_attachment:
        payload = _decode_transfer(
            raw[node.body_start:node.body_end], node.transfer_encoding)
        digest = hashlib.sha256(payload).hexdigest()
        if digest in blocked:
            return _placeholder_part(node), [path]
    return raw[node.start:node.end], []


def _placeholder_part(node: Node) -> bytes:
    kept = [h.raw for h in node.headers
            if not h.name.lower().startswith(b"content-")]
    added = [name + b": " + value
             for name, value in _PLACEHOLDER_CONTENT_HEADERS]
    return b"\r\n".join(kept + added) + b"\r\n\r\n" + PLACEHOLDER_BODY


def inspect(raw: bytes) -> List[Tuple[Path, str]]:
    """Return (path, sha256-hexdigest) for every attachment leaf."""
    return _walk_attachments(raw, _parse_node(raw, 0, len(raw)), ())


def neutralize(
    raw: bytes, blocked_hashes: Sequence[str]
) -> Tuple[bytes, List[Path]]:
    """Replace blacklisted attachments; return (new_bytes, replaced_paths)."""
    blocked = frozenset(h.lower() for h in blocked_hashes)
    return _neutralize_node(raw, _parse_node(raw, 0, len(raw)), (), blocked)
