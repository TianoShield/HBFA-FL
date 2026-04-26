"""Tests for InsightsExtractor.discovery."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import discovery  # noqa: E402


class HelperFunctionsTest(unittest.TestCase):
    def test_parse_base_name_reads_inf_field(self):
        with tempfile.NamedTemporaryFile("w", suffix=".inf", delete=False) as f:
            f.write("[Defines]\n  BASE_NAME = TestFoo\n  FILE_GUID = abc\n")
            p = Path(f.name)
        try:
            self.assertEqual(discovery._parse_base_name(p), "TestFoo")
        finally:
            p.unlink()

    def test_parse_base_name_falls_back_to_stem(self):
        with tempfile.NamedTemporaryFile("w", suffix=".inf",
                                         delete=False, prefix="TestBar_") as f:
            f.write("[Defines]\n  FILE_GUID = abc\n")
            p = Path(f.name)
        try:
            self.assertEqual(discovery._parse_base_name(p), p.stem)
        finally:
            p.unlink()

    def test_is_harness_inf_blocklist(self):
        # We need a path under TESTCASE_ROOT to call _is_harness_inf.
        root = discovery.TESTCASE_ROOT
        # Build hypothetical paths (don't have to exist on disk).
        good = root / "Pkg/Lib/TestFoo.inf"
        bad_prefix = root / "Pkg/Lib/HelperFoo.inf"
        bad_block = root / "Pkg/Lib/TestFooStubLib.inf"
        self.assertTrue(discovery._is_harness_inf(good))
        self.assertFalse(discovery._is_harness_inf(bad_prefix))
        self.assertFalse(discovery._is_harness_inf(bad_block))


class OverridesTest(unittest.TestCase):
    def test_overrides_are_lists_of_strings(self):
        for name, rels in discovery._EDK2_REL_OVERRIDES.items():
            self.assertIsInstance(rels, list, name)
            self.assertGreater(len(rels), 0, name)
            for r in rels:
                self.assertIsInstance(r, str, name)
                self.assertFalse(r.startswith("/"), name)

    def test_virtio_overrides_scope_to_virtiolib(self):
        for name in ("TestVirtioBlk", "TestVirtioBlkReadWrite",
                     "TestVirtioPciDevice", "TestVirtio10Blk"):
            self.assertIn(name, discovery._EDK2_REL_OVERRIDES)
            self.assertEqual(discovery._EDK2_REL_OVERRIDES[name],
                             ["OvmfPkg/Library/VirtioLib"])


class DiscoverHarnessesTest(unittest.TestCase):
    """Live-but-read-only check: must find at least one DSC-registered harness."""

    def setUp(self):
        self.harn = discovery.discover_harnesses()

    def test_finds_at_least_one(self):
        self.assertGreater(len(self.harn), 0)

    def test_required_keys_per_harness(self):
        required = {"inf_abs", "inf_rel", "edk2_rel", "edk2_rels",
                    "binary_afl", "binary_gcc5", "afl_output", "seed_dir"}
        for name, info in self.harn.items():
            self.assertTrue(required.issubset(info), name)
            self.assertEqual(info["edk2_rel"], info["edk2_rels"][0], name)
            self.assertIsInstance(info["edk2_rels"], list, name)
            self.assertTrue(info["inf_abs"].is_file(), name)

    def test_overrides_propagate_to_edk2_rels(self):
        for name, expected in discovery._EDK2_REL_OVERRIDES.items():
            if name in self.harn:
                self.assertEqual(self.harn[name]["edk2_rels"], expected, name)


if __name__ == "__main__":
    unittest.main()
