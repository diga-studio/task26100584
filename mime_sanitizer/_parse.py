"""Byte-preserving MIME parsing primitives.

All spans are (start, end) offsets into the byte string the node was
parsed from.  Nothing in this module ever mutates or re-serializes input;
spans always refer to original (or container-decoded) buffers so callers
can splice replacements without disturbing untouched bytes.
"""

from __future__ import annotations

import base64
import binascii
import quopri
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

CRLF = b"\r\n"
_WSP = b" \t"


@dataclass
class Header:
    """A single (possibly folded) header field."""

    name: str              # lower-cased field name
    value: bytes           # unfolded raw value bytes
    span: Tuple[int, int]  # full span incl. folding and terminating CRLF


@dataclass
class Part:
    """One MIME entity: header block + body, with children for containers."""

    headers: List[Header] = field(default_factory=list)
    header_span: Tuple[int, int] = (0, 0)  # header block, excl. blank line
    body_span: Tuple[int, int] = (0, 0)    # raw (still transfer-encoded) body
    children: List["Part"] = field(default_factory=list)
    # For message/rfc822 the children are parsed from the transfer-decoded
    # payload; `decoded_body` holds those bytes (identity encodings included).
    decoded_body: Optional[bytes] = None

    def header(self, name: str) -> Optional[bytes]:
        for h in self.headers:
            if h.name == name:
                return h.value
        return None


def _unfold(raw: bytes) -> bytes:
    """Unfold a header value: CRLF followed by WSP becomes a single space."""
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        if raw[i:i + 2] == CRLF and i + 2 < n and raw[i + 2:i + 3] in (b" ", b"\t"):
            out += b" "
            i += 2
            while i < n and raw[i:i + 1] in (b" ", b"\t"):
                i += 1
        else:
            out += raw[i:i + 1]
            i += 1
    return bytes(out)


def _parse_headers(data: bytes, start: int) -> Tuple[List[Header], int, int]:
    """Parse the header block beginning at `start`.

    Returns (headers, header_end, body_start) where the header block spans
    [start, header_end) and is followed by a blank line; the body begins at
    body_start.  Each header span includes its terminating CRLF.
    """
    headers: List[Header] = []
    pos = start
    while True:
        nl = data.find(CRLF, pos)
        if nl == -1:
            # No blank line at all: treat the rest as headers, empty body.
            return headers, len(data), len(data)
        if nl == pos:
            # Blank line: header block is [start, pos), body after CRLF.
            return headers, pos, pos + 2
        # One field: consume continuation lines.
        field_end = nl + 2
        while field_end < len(data) and data[field_end:field_end + 1] in (b" ", b"\t"):
            nl = data.find(CRLF, field_end)
            if nl == -1:
                field_end = len(data)
                break
            field_end = nl + 2
        raw = data[pos:field_end]
        if raw.endswith(CRLF):
            raw = raw[:-2]
        name, sep, value = raw.partition(b":")
        if sep:
            unfolded = _unfold(value).strip(b" \t")
            headers.append(Header(name.decode("ascii", "replace").strip().lower(),
                                  unfolded, (pos, field_end)))
        pos = field_end


def _split_params(value: bytes) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
    """Split a header value into main token and ;-separated parameters.

    Double-quoted parameter values may contain ';' and are unquoted here.
    """
    segments: List[bytes] = []
    cur = bytearray()
    in_quote = False
    i = 0
    while i < len(value):
        c = value[i:i + 1]
        if c == b'"':
            in_quote = not in_quote
            cur += c
        elif c == b";" and not in_quote:
            segments.append(bytes(cur))
            cur = bytearray()
        else:
            cur += c
        i += 1
    segments.append(bytes(cur))
    main = segments[0].strip(b" \t").lower() if segments else b""
    params: List[Tuple[bytes, bytes]] = []
    for seg in segments[1:]:
        name, sep, val = seg.partition(b"=")
        if not sep:
            continue
        val = val.strip(b" \t")
        if len(val) >= 2 and val[:1] == b'"' and val[-1:] == b'"':
            val = val[1:-1]
        params.append((name.strip(b" \t").lower(), val))
    return main, params


def content_type(part: Part) -> Tuple[bytes, List[Tuple[bytes, bytes]]]:
    """Return (lowercased type/subtype, params) for a part."""
    value = part.header("content-type")
    if value is None:
        return b"text/plain", []
    return _split_params(value)


def transfer_encoding(part: Part) -> str:
    value = part.header("content-transfer-encoding")
    if value is None:
        return "7bit"
    return value.strip(b" \t").decode("ascii", "replace").lower()


def decode_transfer(data: bytes, encoding: str) -> bytes:
    """Decode a Content-Transfer-Encoding payload."""
    if encoding in ("7bit", "8bit", "binary", ""):
        return data
    if encoding == "base64":
        return base64.b64decode(data, validate=False)
    if encoding == "quoted-printable":
        return quopri.decodestring(data)
    # Unknown encodings are treated as opaque (identity).
    return data


def _find_boundary_lines(data: bytes, start: int, end: int, dash: bytes
                         ) -> List[Tuple[int, int, bool]]:
    """Locate boundary delimiter lines within data[start:end].

    Returns (line_start, content_start, is_close) for each delimiter, where
    content_start is the offset just after the delimiter line's CRLF.
    """
    lines: List[Tuple[int, int, bool]] = []
    pos = start
    while pos <= end - len(dash):
        idx = data.find(dash, pos, end)
        if idx == -1:
            break
        at_line_start = idx == start or data[idx - 2:idx] == CRLF
        if at_line_start:
            rest = idx + len(dash)
            is_close = data[rest:rest + 2] == b"--"
            if is_close:
                rest += 2
            # Optional transport padding, then CRLF (or end of data).
            p = rest
            while p < end and data[p:p + 1] in (b" ", b"\t"):
                p += 1
            if p >= end:
                lines.append((idx, end, is_close))
                break
            if data[p:p + 2] == CRLF:
                lines.append((idx, p + 2, is_close))
                pos = p + 2
                continue
        pos = idx + 1
    return lines


def parse_message(data: bytes, start: int = 0, end: Optional[int] = None) -> Part:
    """Parse a full message (headers + body) into a Part tree."""
    if end is None:
        end = len(data)
    part = Part()
    part.headers, header_end, body_start = _parse_headers(data, start)
    part.header_span = (start, header_end)
    part.body_span = (body_start, end)

    ctype, params = content_type(part)
    if ctype.startswith(b"multipart/"):
        boundary = None
        for name, val in params:
            if name == b"boundary":
                boundary = val
                break
        if boundary:
            dash = b"--" + boundary
            for lines_start, lines_end in _child_spans(
                    data, body_start, end, dash):
                part.children.append(parse_message(data, lines_start, lines_end))
    elif ctype == b"message/rfc822":
        encoding = transfer_encoding(part)
        decoded = decode_transfer(data[body_start:end], encoding)
        part.decoded_body = decoded
        part.children.append(parse_message(decoded))
    return part


def _child_spans(data: bytes, start: int, end: int, dash: bytes
                 ) -> List[Tuple[int, int]]:
    """Content spans of multipart children, excluding delimiter-intro CRLF."""
    spans: List[Tuple[int, int]] = []
    lines = _find_boundary_lines(data, start, end, dash)
    for i, (line_start, content_start, is_close) in enumerate(lines):
        if is_close:
            break
        # Part body ends just before the CRLF introducing the next delimiter.
        if i + 1 < len(lines):
            next_start = lines[i + 1][0]
            part_end = next_start - 2 if next_start >= 2 else next_start
        else:
            part_end = end
        spans.append((content_start, part_end))
    return spans
