import base64
import hashlib
import quopri
import unittest

from mime_sanitizer import inspect, neutralize
from mime_sanitizer._parse import parse_message, decode_transfer, transfer_encoding


def b64(data: bytes) -> bytes:
    return base64.encodebytes(data).replace(b"\n", b"\r\n")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


EVIL = b"MZ\x90\x00 evil-payload-bytes \x00\x01\x02"
EVIL_HASH = sha(EVIL)


def build_repeated_attachments_message() -> bytes:
    """Same evil payload as 3 attachments (base64/qp/8bit) + plain body copy."""
    return (
        b"From: sender@example.com\r\n"
        b"To: rcpt@example.com\r\n"
        b"Subject: repeated\r\n"
        b"Content-Type: multipart/mixed; boundary=\"mix-bound\"\r\n"
        b"\r\n"
        b"the preamble\r\n"
        b"--mix-bound\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"evil-a.exe\"\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"X-Keep-Me: first\r\n"
        b"\r\n"
        + b64(EVIL) +
        b"--mix-bound\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=\"evil-b.exe\"\r\n"
        b"Content-Transfer-Encoding: quoted-printable\r\n"
        b"\r\n"
        + quopri.encodestring(EVIL) +
        b"\r\n--mix-bound\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: inline; filename=\"evil-c.exe\"\r\n"
        b"Content-Transfer-Encoding: 8bit\r\n"
        b"\r\n"
        + EVIL +
        b"\r\n--mix-bound\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"\r\n"
        b"body quoting the same bytes: " + EVIL + b"\r\n"
        b"--mix-bound--\r\n"
        b"the epilogue\r\n"
    )


class RepeatedAttachmentsTest(unittest.TestCase):
    def test_all_encodings_replaced_body_untouched(self):
        raw = build_repeated_attachments_message()
        found = inspect(raw)
        self.assertEqual(found, {(0,): EVIL_HASH, (1,): EVIL_HASH, (2,): EVIL_HASH})

        out, replaced = neutralize(raw, {EVIL_HASH})
        self.assertEqual(sorted(replaced), [(0,), (1,), (2,)])
        self.assertEqual(inspect(out), {})

        # Body part (path (3,)) is byte-identical, including the evil bytes.
        body_marker = b"body quoting the same bytes: " + EVIL
        self.assertIn(body_marker, out)
        # Preamble, epilogue and boundary lines are untouched.
        for kept in (b"the preamble\r\n--mix-bound\r\n",
                     b"\r\n--mix-bound--\r\n",
                     b"the epilogue\r\n"):
            self.assertIn(kept, out)
        # Non-Content-* header of a replaced part survives verbatim.
        self.assertIn(b"X-Keep-Me: first\r\n", out)
        # Placeholder: fixed content, 7bit text/plain, no attachment marker.
        self.assertEqual(out.count(b"Attachment removed"), 3)
        self.assertEqual(out.count(b"Content-Type: text/plain\r\n"
                                   b"Content-Transfer-Encoding: 7bit\r\n"), 3)
        self.assertNotIn(b"Content-Disposition", out)
        self.assertNotIn(b"evil-a.exe", out)
        self.assertNotIn(b"evil-b.exe", out)
        self.assertNotIn(b"evil-c.exe", out)
        # Original untransformed bytes are gone from replaced parts.
        self.assertNotIn(b64(EVIL), out)

    def test_no_hit_returns_input_identical(self):
        raw = build_repeated_attachments_message()
        out, replaced = neutralize(raw, {"0" * 64})
        self.assertEqual(out, raw)
        self.assertEqual(replaced, [])


def build_nested_rfc822_message():
    """base64 message/rfc822 -> multipart/mixed with evil + good attachments."""
    good = b"GOOD-ATTACHMENT-BYTES"
    inner = (
        b"Subject: inner\r\n"
        b"Content-Type: multipart/mixed; boundary=inner-bound\r\n"
        b"\r\n"
        b"inner preamble\r\n"
        b"--inner-bound\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=evil.bin\r\n"
        b"\r\n"
        + EVIL +
        b"\r\n--inner-bound\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=good.bin\r\n"
        b"\r\n"
        + good +
        b"\r\n--inner-bound--\r\n"
        b"inner epilogue\r\n"
    )
    outer = (
        b"From: a@example.com\r\n"
        b"Content-Type: multipart/mixed; boundary=outer-bound\r\n"
        b"\r\n"
        b"--outer-bound\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"see attached message\r\n"
        b"--outer-bound\r\n"
        b"Content-Type: message/rfc822\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"X-Outer: keep\r\n"
        b"\r\n"
        + b64(inner) +
        b"--outer-bound--\r\n"
    )
    return outer, inner, good


class NestedRfc822Test(unittest.TestCase):
    def test_nested_base64_message(self):
        outer, inner, good = build_nested_rfc822_message()
        found = inspect(outer)
        self.assertEqual(found, {(1, 0, 0): EVIL_HASH, (1, 0, 1): sha(good)})

        out, replaced = neutralize(outer, {EVIL_HASH})
        self.assertEqual(replaced, [(1, 0, 0)])

        # Outer container headers untouched; outer text part byte-identical.
        self.assertIn(b"Content-Type: message/rfc822\r\n"
                      b"Content-Transfer-Encoding: base64\r\n"
                      b"X-Outer: keep\r\n", out)
        self.assertIn(b"see attached message\r\n--outer-bound\r\n", out)

        # Decode layer 1: the message/rfc822 payload still base64-decodes
        # to a message whose unchanged regions are byte-identical.
        tree = parse_message(out)
        rfc = tree.children[1]
        decoded = decode_transfer(
            out[rfc.body_span[0]:rfc.body_span[1]], transfer_encoding(rfc))
        self.assertEqual(transfer_encoding(rfc), "base64")
        # Inner preamble, good attachment part and epilogue preserved.
        self.assertIn(b"inner preamble\r\n--inner-bound\r\n", decoded)
        self.assertIn(b"inner epilogue\r\n", decoded)
        good_start = inner.index(b"Content-Type: application/octet-stream\r\n"
                                 b"Content-Disposition: attachment; filename=good.bin")
        good_region = inner[good_start:inner.index(b"\r\n--inner-bound--")]
        self.assertIn(good_region, decoded)
        self.assertIn(good, decoded)
        # Evil payload replaced at the decoded layer.
        self.assertNotIn(EVIL, decoded)
        self.assertIn(b"Attachment removed", decoded)

        # Fingerprints after neutralization: only the good attachment remains.
        self.assertEqual(inspect(out), {(1, 0, 1): sha(good)})

        # Structure not flattened: still nested multipart inside message/rfc822.
        inner_tree = rfc.children[0]
        self.assertEqual(len(inner_tree.children), 2)


def build_tricky_message() -> bytes:
    """Folded headers, quoted boundary, boundary-prefix decoys, trailing CRLF."""
    payload = (
        b"line one\r\n"
        b"--tricky\r\n"          # exact delimiter text as payload content? no:
        # the line above WOULD be a delimiter; use prefix decoys instead:
    )
    payload = (
        b"line one\r\n"
        b"--trick\r\n"           # shorter than boundary
        b"--tricky-b\r\n"        # longer, boundary is a strict prefix
        b" --tricky\r\n"         # not at line start
        b"--trickyX\r\n"         # boundary + junk, not a delimiter
        b"ends with its own CRLF\r\n"
    )
    raw = (
        b"From: a@example.com\r\n"
        b"Content-Type: multipart/mixed;\r\n"
        b"\tboundary=\"tricky\"\r\n"
        b"Subject: folded\r\n"
        b"\tcontinuation line\r\n"
        b"\r\n"
        b"--tricky\r\n"
        b"Content-Type: application/octet-stream;\r\n"
        b"\tname*=utf-8''folded.bin\r\n"
        b"Content-Disposition:\r\n"
        b"\tATTACHMENT;\r\n"
        b"\tfilename=\"tricky.bin\"\r\n"
        b"Content-Transfer-Encoding: 7BIT\r\n"
        b"\r\n"
        + payload +
        b"\r\n--tricky\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"plain body\r\n"
        b"--tricky--\r\n"
    )
    return raw, payload


class TrickyBoundaryTest(unittest.TestCase):
    def test_boundary_location_and_payload_hash(self):
        raw, payload = build_tricky_message()
        # Payload hash covers its own trailing CRLF but not the CRLF that
        # introduces the closing delimiter.
        payload_hash = sha(payload)
        self.assertEqual(inspect(raw), {(0,): payload_hash})

    def test_no_hit_byte_identical(self):
        raw, _ = build_tricky_message()
        out, replaced = neutralize(raw, {"f" * 64})
        self.assertEqual(out, raw)
        self.assertEqual(replaced, [])

    def test_hit_then_hit_again_is_stable(self):
        raw, payload = build_tricky_message()
        payload_hash = sha(payload)
        out1, replaced1 = neutralize(raw, {payload_hash})
        self.assertEqual(replaced1, [(0,)])
        # Second pass with the same blacklist: byte-identical, empty report.
        out2, replaced2 = neutralize(out1, {payload_hash})
        self.assertEqual(out2, out1)
        self.assertEqual(replaced2, [])
        # Folded non-Content headers and the untouched text part survive.
        self.assertIn(b"Subject: folded\r\n\tcontinuation line\r\n", out1)
        self.assertIn(b"plain body\r\n--tricky--\r\n", out1)
        # The decoy lines lived in the replaced payload and are gone.
        self.assertNotIn(b"--trickyX", out1)


if __name__ == "__main__":
    unittest.main()
