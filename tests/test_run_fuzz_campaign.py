"""Tests for InsightsExtractor.run_fuzz_campaign CLI parser."""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import run_fuzz_campaign as rfc  # noqa: E402


class ParseArgsTest(unittest.TestCase):
    def test_defaults(self):
        with mock.patch.object(sys, "argv", ["prog"]):
            args = rfc._parse_args()
        self.assertEqual(args.cores, 4)
        self.assertEqual(args.duration, 1.0)
        self.assertEqual(args.timeout, 5000)
        self.assertIsNone(args.harness)
        self.assertFalse(args.resume)
        self.assertFalse(args.skip_build)
        self.assertFalse(args.skip_fuzz)
        self.assertFalse(args.skip_coverage)
        self.assertFalse(args.skip_crashes)
        self.assertFalse(args.list_only)

    def test_overrides(self):
        argv = ["prog", "--cores", "16", "--duration", "0.5",
                "--timeout", "2000", "--harness", "TestUdf", "TestPartition",
                "--resume", "--skip-build", "--skip-fuzz",
                "--skip-coverage", "--skip-crashes", "--list"]
        with mock.patch.object(sys, "argv", argv):
            args = rfc._parse_args()
        self.assertEqual(args.cores, 16)
        self.assertEqual(args.duration, 0.5)
        self.assertEqual(args.timeout, 2000)
        self.assertEqual(args.harness, ["TestUdf", "TestPartition"])
        self.assertTrue(args.resume)
        self.assertTrue(args.skip_build)
        self.assertTrue(args.skip_fuzz)
        self.assertTrue(args.skip_coverage)
        self.assertTrue(args.skip_crashes)
        self.assertTrue(args.list_only)


class MainListOnlyTest(unittest.TestCase):
    def test_list_path_does_not_build_or_fuzz(self):
        fake_harn = {
            "TestX": {"inf_rel": "Pkg/TestX.inf", "edk2_rel": "Pkg/X"},
        }
        with mock.patch.object(sys, "argv", ["prog", "--list"]), \
             mock.patch.object(rfc, "discover_harnesses",
                               return_value=fake_harn) as disc, \
             mock.patch.object(rfc, "build_harnesses") as bh, \
             mock.patch.object(rfc, "FuzzCampaign") as fc, \
             mock.patch.object(rfc, "collect_coverage") as cc, \
             mock.patch.object(rfc, "collect_crashes") as cr, \
             mock.patch.object(rfc, "write_metrics") as wm:
            rfc.main()
        disc.assert_called_once()
        bh.assert_not_called()
        fc.assert_not_called()
        cc.assert_not_called()
        cr.assert_not_called()
        wm.assert_not_called()


if __name__ == "__main__":
    unittest.main()
