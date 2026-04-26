"""Tests for InsightsExtractor.components (mapping + writers)."""
import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import components  # noqa: E402


SAMPLE_ROWS = [
    {"Component": "MdeModulePkg", "Module": "Universal/Disk/UdfDxe",
     "Harness": "TestUdf",      "edk2 Source": "edk2/MdeModulePkg/Universal/Disk/UdfDxe",
     "INF": "UefiHostFuzzTestCasePkg/TestCase/MdeModulePkg/Universal/Disk/UdfDxe/TestUdf.inf"},
    {"Component": "OvmfPkg", "Module": "Library/VirtioLib",
     "Harness": "TestVirtioBlk", "edk2 Source": "edk2/OvmfPkg/Library/VirtioLib",
     "INF": "UefiHostFuzzTestCasePkg/TestCase/OvmfPkg/VirtioBlkDxe/TestVirtioBlk.inf"},
]


class BuildRowsTest(unittest.TestCase):
    def test_live_rows_have_required_columns(self):
        rows = components.build_rows()
        self.assertGreater(len(rows), 0)
        for r in rows:
            self.assertEqual(set(r), set(components.COLUMNS))
            self.assertTrue(r["edk2 Source"].startswith("edk2/"))


class WriterTest(unittest.TestCase):
    def test_write_csv_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.csv"
            components.write_csv(SAMPLE_ROWS, p)
            with p.open() as f:
                got = list(csv.DictReader(f))
            self.assertEqual(len(got), 2)
            self.assertEqual(got[0]["Harness"], "TestUdf")
            self.assertEqual(set(got[0]), set(components.COLUMNS))

    def test_write_markdown_groups_by_component(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "out.md"
            components.write_markdown(SAMPLE_ROWS, p)
            text = p.read_text()
        self.assertIn("# HBFA Harness", text)
        self.assertIn("## MdeModulePkg", text)
        self.assertIn("## OvmfPkg", text)
        self.assertIn("`TestUdf`", text)
        self.assertIn("`TestVirtioBlk`", text)


if __name__ == "__main__":
    unittest.main()
