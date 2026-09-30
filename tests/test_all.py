import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.encryption import (AuthenticationError, InvalidFormatError, protect_file,
                                 restore_file)
from security.integrity import sha256_file, verify_against_record, verify_with_password
from security.password import analyze_password, generate_password
from storage.metadata import MetadataStore

FAST = 1000  # low iteration count only to keep tests quick


class TestPassword(unittest.TestCase):
    def test_weak_and_strong(self):
        self.assertEqual(analyze_password("password")["label"], "Weak")
        self.assertEqual(analyze_password("Xk9!mQ2#vLp7$wRt")["label"], "Strong")

    def test_generator(self):
        p = generate_password(20)
        self.assertEqual(len(p), 20)
        self.assertEqual(analyze_password(p)["label"], "Strong")


class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.src = self.tmp / "report.txt"
        self.src.write_bytes(b"HELLO WORLD" * 1000)

    def test_roundtrip(self):
        enc = protect_file(self.src, "pw!", iterations=FAST)
        self.assertEqual(enc.name, "report.txt.phkey")
        self.assertNotIn(b"HELLO WORLD", enc.read_bytes())
        (self.tmp / "out").mkdir()
        out = restore_file(enc, "pw!", out_dir=self.tmp / "out")
        self.assertEqual(out.read_bytes(), self.src.read_bytes())
        self.assertEqual(out.name, "report.txt")

    def test_wrong_password(self):
        enc = protect_file(self.src, "right", iterations=FAST)
        for bad in ("wrong", "Right", "righ"):
            with self.assertRaises(AuthenticationError):
                restore_file(enc, bad)

    def test_tamper_detected(self):
        enc = protect_file(self.src, "pw", iterations=FAST)
        blob = bytearray(enc.read_bytes())
        blob[-10] ^= 0x01
        enc.write_bytes(bytes(blob))
        ok, _ = verify_with_password(enc, "pw")
        self.assertFalse(ok)

    def test_invalid_format(self):
        bogus = self.tmp / "x.phkey"
        bogus.write_bytes(b"not a phantom key file at all, sorry")
        with self.assertRaises(InvalidFormatError):
            restore_file(bogus, "pw")

    def test_no_overwrite(self):
        a = protect_file(self.src, "pw", iterations=FAST)
        b = protect_file(self.src, "pw", iterations=FAST)
        self.assertNotEqual(a, b)

    def test_same_file_different_ciphertext(self):
        a = protect_file(self.src, "pw", iterations=FAST).read_bytes()
        b = protect_file(self.src, "pw", iterations=FAST).read_bytes()
        self.assertNotEqual(a, b)  # random salt + IV

    def test_empty_password_rejected(self):
        with self.assertRaises(ValueError):
            protect_file(self.src, "")


class TestIntegrity(unittest.TestCase):
    def test_fingerprint(self):
        tmp = Path(tempfile.mkdtemp())
        src = tmp / "a.txt"
        src.write_text("data")
        enc = protect_file(src, "pw", iterations=FAST)
        digest = sha256_file(enc)
        self.assertTrue(verify_against_record(enc, digest)[0])
        enc.write_bytes(enc.read_bytes() + b"x")
        self.assertFalse(verify_against_record(enc, digest)[0])


class TestMetadata(unittest.TestCase):
    def test_counters(self):
        m = MetadataStore(tempfile.mkdtemp())
        m.record_failure()
        m.record_check()
        self.assertEqual(MetadataStore(m.path.parent).data["failed_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
