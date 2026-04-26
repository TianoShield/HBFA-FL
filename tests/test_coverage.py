"""Tests for InsightsExtractor.coverage pure-logic helpers."""
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from InsightsExtractor import coverage  # noqa: E402


SAMPLE_INFO = textwrap.dedent("""\
    TN:
    SF:/edk2/MyPkg/foo.c
    FN:1,foo
    FN:10,bar
    FNDA:3,foo
    FNDA:0,bar
    FNF:2
    FNH:1
    DA:1,5
    DA:2,0
    DA:3,7
    LF:3
    LH:2
    end_of_record
    SF:/edk2/MyPkg/baz.c
    FN:1,baz
    FNDA:1,baz
    FNF:1
    FNH:1
    DA:1,1
    DA:2,1
    LF:2
    LH:2
    end_of_record
    """)


class ParseLcovInfoTest(unittest.TestCase):
    def test_totals_and_hit_keys(self):
        with tempfile.NamedTemporaryFile("w", suffix=".info",
                                         delete=False) as fh:
            fh.write(SAMPLE_INFO)
            p = Path(fh.name)
        try:
            stats = coverage._parse_lcov_info(p)
        finally:
            p.unlink()

        self.assertEqual(stats["lines_total"], 5)
        self.assertEqual(stats["lines_hit"], 4)
        self.assertEqual(stats["functions_total"], 3)
        self.assertEqual(stats["functions_hit"], 2)

        # Lines with count != 0
        self.assertSetEqual(
            stats["_lines_hit_keys"],
            {"/edk2/MyPkg/foo.c:1", "/edk2/MyPkg/foo.c:3",
             "/edk2/MyPkg/baz.c:1", "/edk2/MyPkg/baz.c:2"})

        # Functions with count != 0
        self.assertSetEqual(
            stats["_fns_hit_keys"],
            {"/edk2/MyPkg/foo.c::foo", "/edk2/MyPkg/baz.c::baz"})

    def test_missing_file_returns_empty(self):
        stats = coverage._parse_lcov_info(Path("/no/such/file.info"))
        self.assertEqual(stats["lines_total"], 0)
        self.assertEqual(stats["functions_total"], 0)
        self.assertEqual(stats["_lines_hit_keys"], set())
        self.assertEqual(stats["_fns_hit_keys"], set())


@unittest.skipIf(coverage._TS_PARSER is None,
                 "tree-sitter / tree_sitter_c not installed")
class TreeSitterMetricsTest(unittest.TestCase):
    SAMPLE_C = textwrap.dedent("""\
        #include <stdio.h>

        int g_counter = 0;     /* global decl, not in any function */

        static int helper(int x) {
            int y = x + 1;     /* declaration */
            if (y > 0) {       /* if_statement */
                return y;      /* return_statement */
            }
            return 0;          /* return_statement */
        }

        int main(void) {
            return helper(42); /* return_statement */
        }
        """)

    def test_count_source_metrics(self):
        with tempfile.NamedTemporaryFile("w", suffix=".c",
                                         delete=False) as fh:
            fh.write(self.SAMPLE_C)
            p = Path(fh.name)
        try:
            lines, funcs = coverage._count_source_metrics(p)
        finally:
            p.unlink()
        # Two function definitions: helper, main
        self.assertEqual(funcs, 2)
        # At least 4 distinct statement-bearing lines inside functions
        # (declaration, if, two returns inside helper, return in main).
        self.assertGreaterEqual(lines, 4)

    def test_count_source_metrics_missing_file(self):
        self.assertEqual(coverage._count_source_metrics(Path("/no/such.c")),
                         (0, 0))


class ComponentTotalsCacheTest(unittest.TestCase):
    def test_cache_returns_same_object(self):
        # Use a real edk2 component (PartitionDxe) so the walk has work to do.
        rel = "MdeModulePkg/Universal/Disk/PartitionDxe"
        if not (coverage.EDK2_DIR / rel).is_dir():
            self.skipTest(f"{rel} not present in workspace")
        coverage._COMPONENT_TOTAL_CACHE.pop(rel, None)
        a = coverage._component_totals(rel)
        b = coverage._component_totals(rel)
        self.assertEqual(a, b)
        self.assertIn(rel, coverage._COMPONENT_TOTAL_CACHE)
        # Lines + funcs must be > 0 for a real component (assuming
        # tree-sitter is installed).
        if coverage._TS_PARSER is not None:
            self.assertGreater(a[0], 0)
            self.assertGreater(a[1], 0)

    def test_unknown_component_returns_zero(self):
        rel = "Nonexistent/Pkg/Foo"
        coverage._COMPONENT_TOTAL_CACHE.pop(rel, None)
        self.assertEqual(coverage._component_totals(rel), (0, 0))


if __name__ == "__main__":
    unittest.main()
