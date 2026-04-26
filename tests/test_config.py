"""Smoke tests for the workspace-discovery constants in config.py."""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import config  # noqa: E402


class ConfigPathsTest(unittest.TestCase):
    def test_workspace_contains_edk2_and_hbfa(self):
        self.assertTrue((config.WORKSPACE / "edk2").is_dir())
        self.assertTrue((config.WORKSPACE / "HBFA").is_dir())

    def test_hbfa_pkg_dir_resolves(self):
        self.assertTrue(config.HBFA_PKG_DIR.is_dir(),
                        f"missing {config.HBFA_PKG_DIR}")
        self.assertTrue(config.TESTCASE_ROOT.is_dir())
        self.assertTrue((config.HBFA_PKG_DIR /
                         f"{config.HBFA_PKG_NAME}.dsc").is_file())

    def test_data_paths_under_insights(self):
        self.assertEqual(config.COVERAGE_CSV.parent, config.DATA_DIR)
        self.assertEqual(config.CRASHES_CSV.parent, config.DATA_DIR)
        self.assertEqual(config.METRICS_XLSX.parent, config.DATA_DIR)
        self.assertEqual(config.CRASH_SEED_DIR.parent, config.DATA_DIR)

    def test_afl_output_prefix_is_str(self):
        # AFL_OUTPUT_PREFIX is a string with trailing context, not a Path,
        # because callers concatenate the harness name onto it.
        self.assertIsInstance(config.AFL_OUTPUT_PREFIX, str)
        self.assertTrue(config.AFL_OUTPUT_PREFIX.endswith("afl_out_"))

    def test_arch_target_defaults(self):
        self.assertEqual(config.DEFAULT_ARCH, "X64")
        self.assertEqual(config.DEFAULT_TARGET, "DEBUG")


if __name__ == "__main__":
    unittest.main()
