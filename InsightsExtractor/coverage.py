# =============================================================================
# coverage.py — Replay AFL queue through GCC5 binary and capture lcov
# =============================================================================

"""Per-harness line+function coverage scoped to its actual edk2 source dir."""

import csv
import os
import subprocess
from pathlib import Path

from .config import BUILD_GCC5_DIR, COVERAGE_CSV, EDK2_DIR


# --------------------------------------------------------------------------
# Component-level totals (tree-sitter parser, gcov-equivalent)
#
# lcov reports LF/FNF only for the source files actually compiled into the
# harness binary, so a harness like TestFileName (which only links
# UdfDxe/FileName.c) reports lines_total=89 — making "100 % coverage" look
# meaningless. The denominator we want is the *whole* edk2 component on
# disk (e.g. all of edk2/MdeModulePkg/Universal/Disk/UdfDxe).
#
# We use tree-sitter's C grammar to walk every .c file under a component
# and emulate gcov's notion of an "instrumentable line":
#   - Walk every `function_definition` node.
#   - Inside its body, every statement-like node contributes its start
#     line to a set; gcov counts each distinct line once.
#   - Functions are counted from `function_definition` nodes themselves.
# Empirically this matches gcov's LF/FNF within ~1% on fully-compiled
# components (UdfDxe: ~1335; PartitionDxe: ~1005).
# --------------------------------------------------------------------------

try:
    import tree_sitter
    import tree_sitter_c
    _TS_LANG = tree_sitter.Language(tree_sitter_c.language())
    _TS_PARSER = tree_sitter.Parser(_TS_LANG)
except Exception as _e:                     # pragma: no cover - install issue
    _TS_PARSER = None
    print(f"[coverage] tree-sitter unavailable ({_e}); component totals "
          "will be 0. Install with: pip install tree_sitter tree_sitter_c")

# Statement-like node kinds that gcov instruments (one count per unique
# starting line). Compound statements / declaration_lists themselves are
# skipped — only their individual children count.
_STMT_KINDS = frozenset({
    "expression_statement",
    "if_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "case_statement",
    "return_statement",
    "break_statement",
    "continue_statement",
    "goto_statement",
    "labeled_statement",
    "declaration",          # locals with initializers / side effects
})

# Subdir name fragments to skip when walking a component directory: these
# hold unit tests, not the production component code.
_COMPONENT_SKIP_DIRS = ("UnitTest", "GoogleTest", "HostTest")


def _count_source_metrics(c_path: Path) -> tuple[int, int]:
    """Return (instrumentable_line_count, function_count) for a .c file."""
    if _TS_PARSER is None:
        return 0, 0
    try:
        src = c_path.read_bytes()
    except OSError:
        return 0, 0

    tree = _TS_PARSER.parse(src)
    funcs = 0
    lines: set[int] = set()

    cursor_stack = [tree.root_node]
    while cursor_stack:
        node = cursor_stack.pop()
        if node.type == "function_definition":
            funcs += 1
            # Walk just this function's subtree for statement lines so we
            # ignore top-level declarations / globals (gcov doesn't
            # instrument those).
            sub = [node]
            while sub:
                n = sub.pop()
                if n.type in _STMT_KINDS:
                    lines.add(n.start_point[0])
                # Always recurse — statements can be nested arbitrarily.
                sub.extend(n.children)
            # Don't recurse into this node again from the outer walk.
            continue
        cursor_stack.extend(node.children)

    return len(lines), funcs


_COMPONENT_TOTAL_CACHE: dict[str, tuple[int, int]] = {}


def _component_totals(rel: str) -> tuple[int, int]:
    """Return (total_lines, total_functions) for an edk2-relative dir."""
    if rel in _COMPONENT_TOTAL_CACHE:
        return _COMPONENT_TOTAL_CACHE[rel]
    root = EDK2_DIR / rel
    total_lines = total_funcs = 0
    if root.is_dir():
        for p in root.rglob("*.c"):
            if any(skip in p.parts for skip in _COMPONENT_SKIP_DIRS):
                continue
            l, f = _count_source_metrics(p)
            total_lines += l
            total_funcs += f
    _COMPONENT_TOTAL_CACHE[rel] = (total_lines, total_funcs)
    return total_lines, total_funcs


def _delete_gcda(root: Path) -> None:
    for r, _, files in os.walk(root):
        for f in files:
            if f.endswith(".gcda"):
                try:
                    os.remove(os.path.join(r, f))
                except OSError:
                    pass


def _replay_inputs(binary: Path, input_dir: Path, timeout_s: int = 10) -> None:
    if not input_dir.is_dir():
        return
    for fname in sorted(os.listdir(input_dir)):
        fpath = input_dir / fname
        if not fpath.is_file() or fname.startswith("."):
            continue
        try:
            subprocess.run([str(binary), str(fpath)], timeout=timeout_s,
                           stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        except (subprocess.TimeoutExpired, OSError):
            pass


def _parse_lcov_info(info_file: Path) -> dict:
    lt = lh = ft = fh = 0
    if not info_file.is_file():
        return {"lines_total": 0, "lines_hit": 0,
                "functions_total": 0, "functions_hit": 0,
                "_lines_hit_keys": set(),
                "_fns_hit_keys":   set()}
    # `_lines_hit_keys` / `_fns_hit_keys` collect "<src>:<n>" / "<src>::<fn>"
    # tags so callers can union them across harnesses to compute true
    # component-level coverage (a function missed by harness A but hit by
    # harness B is "covered" once at the component level).
    lines_hit_keys: set = set()
    fns_hit_keys:   set = set()
    cur_src = ""
    with open(info_file) as f:
        for ln in f:
            ln = ln.strip()
            if   ln.startswith("SF:"):  cur_src = ln[3:]
            elif ln.startswith("LF:"):  lt += int(ln[3:])
            elif ln.startswith("LH:"):  lh += int(ln[3:])
            elif ln.startswith("FNF:"): ft += int(ln[4:])
            elif ln.startswith("FNH:"): fh += int(ln[4:])
            elif ln.startswith("DA:"):
                # DA:<line>,<count>[,<checksum>]
                parts = ln[3:].split(",")
                if len(parts) >= 2 and parts[1] != "0":
                    lines_hit_keys.add(f"{cur_src}:{parts[0]}")
            elif ln.startswith("FNDA:"):
                # FNDA:<count>,<name>
                parts = ln[5:].split(",", 1)
                if len(parts) == 2 and parts[0] != "0":
                    fns_hit_keys.add(f"{cur_src}::{parts[1]}")
    return {"lines_total": lt, "lines_hit": lh,
            "functions_total": ft, "functions_hit": fh,
            "_lines_hit_keys": lines_hit_keys,
            "_fns_hit_keys":   fns_hit_keys}


def _extract_stats(raw: Path, name: str, tag: str, patterns: list) -> dict:
    """Run lcov --extract with the given patterns and parse LF/LH/FNF/FNH."""
    out = Path(f"/tmp/cov_{name}_{tag}.info")
    r = subprocess.run(
        ["lcov", "--extract", str(raw), *patterns,
         "--output-file", str(out), "--quiet"],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not out.is_file():
        try: out.unlink()
        except OSError: pass
        return {"lines_total": 0, "lines_hit": 0,
                "functions_total": 0, "functions_hit": 0,
                "_lines_hit_keys": set(),
                "_fns_hit_keys":   set()}
    stats = _parse_lcov_info(out)
    try: out.unlink()
    except OSError: pass
    return stats


def collect_for_harness(name: str, info: dict) -> list | None:
    """Return a list of per-component stats dicts (plus an ALL aggregate row),
    or None if the binary is missing / lcov capture fails."""
    binary = info["binary_gcc5"]
    if not binary.is_file():
        print(f"  SKIP {name}: GCC5 binary missing ({binary})")
        return None

    # Locate AFL queue dir(s) and feed them all
    queue_dirs = []
    afl_out = info["afl_output"]
    if afl_out.is_dir():
        for sub in sorted(afl_out.iterdir()):
            q = sub / "queue"
            if q.is_dir():
                queue_dirs.append(q)
        crashes = [sub / "crashes" for sub in afl_out.iterdir()
                   if (sub / "crashes").is_dir()]
    else:
        crashes = []

    print(f"  [{name}] resetting gcda counters")
    _delete_gcda(BUILD_GCC5_DIR)

    if info["seed_dir"].is_dir():
        _replay_inputs(binary, info["seed_dir"])
    for q in queue_dirs:
        print(f"  [{name}] replaying {len(os.listdir(q))} queue files from {q}")
        _replay_inputs(binary, q)
    for c in crashes:
        _replay_inputs(binary, c)

    raw = Path(f"/tmp/cov_{name}_raw.info")
    r = subprocess.run(
        ["lcov", "--capture", "--directory", str(BUILD_GCC5_DIR),
         "--output-file", str(raw), "--quiet",
         "--rc", "lcov_branch_coverage=0"],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not raw.is_file():
        print(f"  WARN {name}: lcov capture failed: {r.stderr[:200]}")
        return None

    # Build one stats row per individual edk2 component the harness
    # exercises, plus an aggregate "ALL" row covering them all together.
    # Each row carries the harness name + component path so the CSV is
    # easy to slice in Excel.
    edk2_rels = info.get("edk2_rels") or [info["edk2_rel"]]
    results = []
    for rel in edk2_rels:
        s = _extract_stats(raw, name, rel.replace("/", "_"),
                           [f"*/edk2/{rel}/*"])
        # Override the denominator with the *whole* component on disk so
        # that uncompiled .c files in the same module count against the
        # harness ("component-level" coverage). Numerator (hits) stays as
        # what lcov actually observed.
        ct_lines, ct_funcs = _component_totals(rel)
        if ct_lines: s["lines_total"]     = ct_lines
        if ct_funcs: s["functions_total"] = ct_funcs
        # Cap hits at total in case the regex undercounts an unusual file.
        s["lines_hit"]     = min(s["lines_hit"],     s["lines_total"])
        s["functions_hit"] = min(s["functions_hit"], s["functions_total"])
        s["component"] = rel
        results.append(s)
    if len(edk2_rels) > 1:
        agg = _extract_stats(raw, name, "ALL",
                             [f"*/edk2/{rel}/*" for rel in edk2_rels])
        agg_lines = sum(_component_totals(r)[0] for r in edk2_rels)
        agg_funcs = sum(_component_totals(r)[1] for r in edk2_rels)
        if agg_lines: agg["lines_total"]     = agg_lines
        if agg_funcs: agg["functions_total"] = agg_funcs
        agg["lines_hit"]     = min(agg["lines_hit"],     agg["lines_total"])
        agg["functions_hit"] = min(agg["functions_hit"], agg["functions_total"])
        agg["component"] = "ALL (" + ";".join(edk2_rels) + ")"
        results.append(agg)

    try: raw.unlink()
    except OSError: pass

    return results


def collect_all(harnesses: dict) -> list:
    """Compute coverage for every harness, write CSV, return list of rows."""
    print(f"\n[coverage] collecting per-harness coverage...")
    fieldnames = [
        "harness", "component",
        "lines_total", "lines_hit", "line_coverage_pct",
        "functions_total", "functions_hit", "function_coverage_pct",
    ]
    COVERAGE_CSV.parent.mkdir(parents=True, exist_ok=True)
    # Open CSV up front so partial runs still leave a usable file.
    csv_fh = open(COVERAGE_CSV, "w", newline="")
    writer = csv.DictWriter(csv_fh, fieldnames=fieldnames)
    writer.writeheader()
    csv_fh.flush()

    rows = []
    try:
        for name, info in sorted(harnesses.items()):
            edk2_rels = info.get("edk2_rels") or [info["edk2_rel"]]
            try:
                per_comp = collect_for_harness(name, info)
            except Exception as e:
                print(f"  WARN {name}: coverage collection failed: {e}")
                per_comp = None
            if not per_comp:
                # Still emit a row per declared component so every harness
                # is represented in the sheet.
                per_comp = [{"component": rel,
                             "lines_total": 0, "lines_hit": 0,
                             "functions_total": 0, "functions_hit": 0}
                            for rel in edk2_rels]

            for stats in per_comp:
                lt, lh = stats["lines_total"], stats["lines_hit"]
                ft, fh = stats["functions_total"], stats["functions_hit"]
                line_pct = round(100.0 * lh / lt, 2) if lt else 0.0
                fn_pct   = round(100.0 * fh / ft, 2) if ft else 0.0
                row = {
                    "harness":               name,
                    "component":             stats["component"],
                    "lines_total":           lt,
                    "lines_hit":             lh,
                    "line_coverage_pct":     line_pct,
                    "functions_total":       ft,
                    "functions_hit":         fh,
                    "function_coverage_pct": fn_pct,
                }
                # Carry the raw hit-key sets for the union summary in
                # metrics.py. These never go to CSV (csv.DictWriter is
                # given a fixed fieldnames list).
                row["_lines_hit_keys"] = stats.get("_lines_hit_keys", set())
                row["_fns_hit_keys"]   = stats.get("_fns_hit_keys",   set())
                rows.append(row)
                writer.writerow({k: row[k] for k in fieldnames})
                csv_fh.flush()
                print(f"  {name} [{stats['component']}]: "
                      f"lines {lh}/{lt} ({line_pct}%), "
                      f"functions {fh}/{ft} ({fn_pct}%)")
    finally:
        csv_fh.close()
    print(f"[coverage] wrote {COVERAGE_CSV}")
    return rows
