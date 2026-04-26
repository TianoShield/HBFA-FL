"""Tests for InsightsExtractor.crashes pure-logic helpers."""
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import crashes  # noqa: E402


ASAN_HEAP_OVERFLOW = textwrap.dedent("""\
    ==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
        #0 0x7f12 in ParseFoo /home/me/edk2/MdeModulePkg/Universal/Disk/UdfDxe/File.c:42
        #1 0x7f34 in main /home/me/edk2/MdeModulePkg/Universal/Disk/UdfDxe/Main.c:9
    allocated by thread T0 here:
        #0 0x7000 in malloc somewhere.c:1
""")


ASAN_NO_EDK2_FRAMES = textwrap.dedent("""\
    ==1234==ERROR: AddressSanitizer: stack-overflow on address 0x...
        #0 0x7f12 in libc_func /usr/lib/libc.so:42
""")


SEGV_TEXT = "AddressSanitizer:DEADLYSIGNAL\nSEGV at 0x000000000\n"


class FingerprintTest(unittest.TestCase):
    def test_heap_overflow_uses_first_edk2_frame(self):
        err, fp = crashes._fingerprint(ASAN_HEAP_OVERFLOW)
        self.assertEqual(err, "heap-buffer-overflow")
        self.assertEqual(
            fp,
            "heap-buffer-overflow|ParseFoo:"
            "MdeModulePkg/Universal/Disk/UdfDxe/File.c:42")

    def test_no_edk2_frames_falls_back_to_any_frame(self):
        err, fp = crashes._fingerprint(ASAN_NO_EDK2_FRAMES)
        self.assertEqual(err, "stack-overflow")
        self.assertIn("libc_func", fp)
        self.assertIn("libc.so", fp)

    def test_segv_without_asan_header(self):
        err, fp = crashes._fingerprint(SEGV_TEXT)
        self.assertEqual(err, "SEGV")
        # No frames -> noframes sentinel
        self.assertTrue(fp.endswith("|noframes") or "SEGV|" in fp)

    def test_empty_output(self):
        err, fp = crashes._fingerprint("")
        self.assertEqual(err, "no-output")
        self.assertEqual(fp, "no-output")

    def test_dedupes_identical_inputs(self):
        a = crashes._fingerprint(ASAN_HEAP_OVERFLOW)
        b = crashes._fingerprint(ASAN_HEAP_OVERFLOW)
        self.assertEqual(a, b)


class ListCrashesTest(unittest.TestCase):
    def test_walks_subdir_crashes_folders(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for sub in ("main", "sec01"):
                cdir = root / sub / "crashes"
                cdir.mkdir(parents=True)
                (cdir / "id:000000,sig:11").write_bytes(b"x")
                (cdir / "README.txt").write_text("ignore me")
            (root / "no_crashes_subdir").mkdir()
            files = crashes._list_crashes(root)
            self.assertEqual(len(files), 2)
            for f in files:
                self.assertTrue(f.name.startswith("id:"))

    def test_missing_dir_returns_empty(self):
        self.assertEqual(crashes._list_crashes(Path("/no/such/dir")), [])


class AsanFrameRegexTest(unittest.TestCase):
    def test_matches_typical_frame(self):
        line = "    #0 0x7f12 in ParseFoo /path/to/File.c:42"
        m = crashes._ASAN_FRAME_RE.search(line)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "ParseFoo")
        self.assertEqual(m.group(2), "/path/to/File.c")
        self.assertEqual(m.group(3), "42")


if __name__ == "__main__":
    unittest.main()
