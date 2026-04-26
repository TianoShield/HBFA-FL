# InsightsExtractor unit tests

Run with stdlib unittest (no extra deps):

```bash
cd /home/hbfafl/workspace
python3 -m unittest discover -s tests -v
```

Or run a single module:

```bash
python3 -m unittest tests.test_coverage -v
```

The tests are designed to be hermetic: nothing here actually launches
`afl-fuzz`, `lcov`, or `build`. Subprocess-heavy modules
(`builder`, `campaign`, `crashes`, `coverage.collect_for_harness`,
`coverage.collect_all`) are exercised only at the pure-Python level by
mocking external binaries or by feeding canned inputs (e.g. a
hand-crafted `.info` file or a tiny C source for tree-sitter).
