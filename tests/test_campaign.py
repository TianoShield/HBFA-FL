"""Tests for InsightsExtractor.campaign helpers (no real AFL launched)."""
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import campaign  # noqa: E402


class SyntheticSeedsTest(unittest.TestCase):
    def test_all_non_empty(self):
        seeds = campaign._synthetic_seeds()
        self.assertGreater(len(seeds), 0)
        for label, data in seeds:
            self.assertIsInstance(label, str)
            self.assertIsInstance(data, (bytes, bytearray))
            self.assertGreater(len(data), 0,
                               f"AFL rejects empty seeds: {label}")

    def test_unique_labels(self):
        labels = [lab for lab, _ in campaign._synthetic_seeds()]
        self.assertEqual(len(labels), len(set(labels)))


class AflEnvTest(unittest.TestCase):
    def test_required_keys_present(self):
        env = campaign._afl_env()
        for k in ("AFL_SKIP_CPUFREQ", "AFL_NO_AFFINITY",
                  "AFL_AUTORESUME", "AFL_SKIP_CRASHES",
                  "ASAN_OPTIONS"):
            self.assertIn(k, env)
        # AFL 2.52b refuses to start without abort_on_error=1.
        self.assertIn("abort_on_error=1", env["ASAN_OPTIONS"])

    def test_extra_overrides(self):
        env = campaign._afl_env({"FOO": "bar"})
        self.assertEqual(env["FOO"], "bar")


class TailLogTest(unittest.TestCase):
    def test_returns_last_n_nonblank(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as fh:
            fh.write("a\n\nb\nc\n\nd\n")
            p = Path(fh.name)
        try:
            self.assertEqual(campaign._tail_log(p, 2), ["c", "d"])
            self.assertEqual(campaign._tail_log(p, 10), ["a", "b", "c", "d"])
        finally:
            p.unlink()

    def test_missing_file(self):
        self.assertEqual(campaign._tail_log(Path("/no/such"), 5), [])


class AvailableCoresTest(unittest.TestCase):
    def test_returns_sorted_int_list(self):
        cores = campaign.FuzzCampaign._available_cores()
        self.assertIsInstance(cores, list)
        self.assertGreater(len(cores), 0)
        self.assertTrue(all(isinstance(c, int) for c in cores))
        self.assertEqual(cores, sorted(cores))


class CleanupOutputsTest(unittest.TestCase):
    def test_removes_existing_dirs(self):
        with tempfile.TemporaryDirectory() as td:
            d1 = Path(td) / "afl_out_A"
            d2 = Path(td) / "afl_out_B"
            d1.mkdir()
            d2.mkdir()
            (d1 / "queue").mkdir()
            harn = {
                "A": {"afl_output": d1},
                "B": {"afl_output": d2},
            }
            campaign.cleanup_outputs(harn)
            self.assertFalse(d1.exists())
            self.assertFalse(d2.exists())

    def test_silently_ignores_missing(self):
        harn = {"A": {"afl_output": Path("/no/such/dir/ever")}}
        # Must not raise.
        campaign.cleanup_outputs(harn)


class AflFuzzBinTest(unittest.TestCase):
    def test_respects_afl_path_env(self):
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "afl-fuzz"
            fake.write_text("#!/bin/sh\n")
            fake.chmod(0o755)
            old = os.environ.get("AFL_PATH")
            os.environ["AFL_PATH"] = td
            try:
                self.assertEqual(campaign._afl_fuzz_bin(), str(fake))
            finally:
                if old is None:
                    os.environ.pop("AFL_PATH", None)
                else:
                    os.environ["AFL_PATH"] = old


if __name__ == "__main__":
    unittest.main()
