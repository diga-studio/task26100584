import unittest

import mime_sanitize as ms


PAYLOAD = b"BAD=PAYLOAD\x00\xff bytes"


def _sha256(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


class TestRepeatedMalware(unittest.TestCase):
    def test_repeated_attachment_varied_encodings(self):
        body_text = b"inline body mentions " + PAYLOAD + b" verbatim"
        raw = (
            b"From: a@b.c\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BB\"\r\n"
            b"\r\n"
            b"preamble\r\n"
            b"--BB\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n" + body_text + b"\r\n"
            b"--BB\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"evil1.bin\"\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"QkFEPVBBWUxPQUQA/yBieXRlcw==\r\n"
            b"--BB\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"evil2.bin\"\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"BAD=3DPAYLOAD=00=FF=20bytes\r\n"
            b"--BB--\r\n"
            b"epilogue"
        )
        digest = _sha256(PAYLOAD)

        found = ms.inspect(raw)
        self.assertEqual(found, [((1,), digest), ((2,), digest)])

        out, replaced = ms.neutralize(raw, [digest])
        self.assertEqual(replaced, [(1,), (2,)])

        # Body part with identical bytes but no attachment marker survives.
        self.assertIn(body_text, out)
        # Placeholder substituted for both attachments.
        self.assertEqual(out.count(b"Attachment removed"), 2)
        self.assertNotIn(b"evil1.bin", out)
        self.assertNotIn(b"evil2.bin", out)
        self.assertNotIn(b"QkFEPVBBWUxPQUQA/yBieXRlcw==", out)
        # Untouched regions are byte-identical.
        self.assertTrue(out.startswith(b"From: a@b.c\r\n"))
        self.assertIn(b"preamble\r\n--BB\r\n", out)
        self.assertTrue(out.endswith(b"--BB--\r\nepilogue"))
        # Remaining attachments: none listed anymore.
        self.assertEqual(ms.inspect(out), [])
        # Second pass is a byte-identical no-op.
        out2, replaced2 = ms.neutralize(out, [digest])
        self.assertEqual(out2, out)
        self.assertEqual(replaced2, [])


class TestNestedEncodedMessage(unittest.TestCase):
    def test_base64_rfc822_with_mixed_parts(self):
        import base64

        evil = b"EVIL-NESTED-PAYLOAD"
        good = b"GOOD-NESTED-PAYLOAD"
        inner = (
            b"Content-Type: multipart/mixed; boundary=IN\r\n"
            b"X-Inner: keep\r\n"
            b"\r\n"
            b"--IN\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Disposition: attachment; filename=\"evil.bin\"\r\n"
            b"\r\n" + evil + b"\r\n"
            b"--IN\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Disposition: attachment; filename=\"good.txt\"\r\n"
            b"\r\n" + good + b"\r\n"
            b"--IN--\r\n"
        )
        encoded = base64.b64encode(inner)
        wrapped = b"\r\n".join(
            encoded[i:i + 76] for i in range(0, len(encoded), 76))
        raw = (
            b"Content-Type: message/rfc822\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n" + wrapped + b"\r\n"
        )
        evil_digest = _sha256(evil)
        good_digest = _sha256(good)

        found = ms.inspect(raw)
        self.assertEqual(
            found, [((0, 0), evil_digest), ((0, 1), good_digest)])

        out, replaced = ms.neutralize(raw, [evil_digest])
        self.assertEqual(replaced, [(0, 0)])

        # Outer message headers are byte-identical.
        outer_head = raw.split(b"\r\n\r\n", 1)[0]
        self.assertEqual(out.split(b"\r\n\r\n", 1)[0], outer_head)

        # Decode both payload layers and compare decoded regions.
        new_inner = base64.b64decode(out.split(b"\r\n\r\n", 1)[1])
        old_segments = inner.split(b"--IN\r\n")
        new_segments = new_inner.split(b"--IN\r\n")
        self.assertEqual(len(new_segments), len(old_segments))
        # Inner headers/preamble untouched.
        self.assertEqual(new_segments[0], old_segments[0])
        # Good attachment and closing boundary byte-identical.
        self.assertEqual(new_segments[2], old_segments[2])
        self.assertIn(good, new_segments[2])
        # Evil part became the placeholder.
        self.assertNotIn(evil, new_inner)
        self.assertEqual(new_segments[1],
                         b"Content-Type: text/plain\r\n"
                         b"Content-Transfer-Encoding: 7bit\r\n"
                         b"\r\nAttachment removed\r\n")

        # Structure and fingerprints after neutralizing.
        self.assertEqual(ms.inspect(out), [((0, 1), good_digest)])

        # Second pass is a byte-identical no-op.
        out2, replaced2 = ms.neutralize(out, [evil_digest])
        self.assertEqual(out2, out)
        self.assertEqual(replaced2, [])


class TestBoundaryAndIdempotence(unittest.TestCase):
    def test_folded_headers_quoted_boundary_crlf_idempotent(self):
        hit_payload = (
            b"first line\r\n"
            b"--Q BX same-prefix, not a delimiter\r\n"
            b"--Q B--x not the closing delimiter\r\n"
            b"last line\r\n"
        )
        miss_payload = b"MISS-PAYLOAD\r\n"
        hit_part = (
            b"content-type: application/octet-stream\r\n"
            b"Content-Disposition: attachment;\r\n"
            b"\tfilename=\"fold.bin\"\r\n"
            b"X-Custom-Long: first\r\n"
            b"\tsecond\r\n"
            b"CONTENT-TRANSFER-ENCODING: 7bit\r\n"
            b"\r\n" + hit_payload
        )
        miss_part = (
            b"Content-Type: text/plain\r\n"
            b"Content-Disposition: attachment; filename=\"miss.txt\"\r\n"
            b"\r\n" + miss_payload
        )
        text_part = b"Content-Type: TEXT/PLAIN\r\n\r\nplain body"
        raw = (
            b"Content-Type: multipart/mixed;\r\n"
            b"\tboundary=\"Q B\"\r\n"
            b"\r\n"
            b"preamble\r\n"
            b"--Q B\r\n" + text_part + b"\r\n"
            b"--Q B\r\n" + hit_part + b"\r\n"
            b"--Q B\r\n" + miss_part + b"\r\n"
            b"--Q B--\r\n"
            b"epilogue"
        )
        hit_digest = _sha256(hit_payload)
        miss_digest = _sha256(miss_payload)

        # Boundary detection despite quoted boundary, folded headers,
        # payload trailing CRLF, and delimiter look-alike lines.
        found = ms.inspect(raw)
        self.assertEqual(found, [((1,), hit_digest), ((2,), miss_digest)])

        # No hit: output is byte-identical to input.
        same, replaced = ms.neutralize(raw, [])
        self.assertEqual(same, raw)
        self.assertEqual(replaced, [])
        same, replaced = ms.neutralize(raw, [_sha256(b"absent")])
        self.assertEqual(same, raw)
        self.assertEqual(replaced, [])

        out, replaced = ms.neutralize(raw, [hit_digest])
        self.assertEqual(replaced, [(1,)])

        # Untouched parts and framing survive byte-for-byte.
        self.assertIn(text_part, out)
        self.assertIn(miss_part, out)
        self.assertTrue(out.startswith(
            b"Content-Type: multipart/mixed;\r\n\tboundary=\"Q B\"\r\n"
            b"\r\npreamble\r\n--Q B\r\n"))
        self.assertTrue(out.endswith(b"--Q B--\r\nepilogue"))
        # Folded non-Content header of the hit part is preserved as-is.
        self.assertIn(b"X-Custom-Long: first\r\n\tsecond\r\n", out)
        # Hit payload (including its look-alike lines) is gone.
        self.assertNotIn(b"--Q BX same-prefix", out)
        self.assertNotIn(b"last line", out)
        self.assertEqual(ms.inspect(out), [((2,), miss_digest)])

        # Continuous double neutralization is a byte-identical no-op.
        out2, replaced2 = ms.neutralize(out, [hit_digest])
        self.assertEqual(out2, out)
        self.assertEqual(replaced2, [])


if __name__ == "__main__":
    unittest.main()
