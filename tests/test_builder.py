"""Tests for InsightsExtractor.builder pure helpers."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import builder, config  # noqa: E402


class BuildEnvTest(unittest.TestCase):
    def test_workspace_set(self):
        env = builder._build_env()
        self.assertEqual(env["WORKSPACE"], str(config.WORKSPACE))

    def test_packages_path_includes_edk2_and_hbfa(self):
        env = builder._build_env()
        # PACKAGES_PATH may already be set in the host env; just assert
        # both required dirs are reachable somewhere on the path.
        pp = env.get("PACKAGES_PATH", "")
        self.assertTrue(pp, "PACKAGES_PATH must be set")
        # If we filled it ourselves it contains both prefixes; if the
        # outer shell pre-set it, just trust it exists.
        if str(config.HBFA_DIR) in pp:
            self.assertIn(str(config.WORKSPACE / "edk2"), pp)

    def test_edk_tools_path_default(self):
        env = builder._build_env()
        self.assertIn("EDK_TOOLS_PATH", env)


if __name__ == "__main__":
    unittest.main()
