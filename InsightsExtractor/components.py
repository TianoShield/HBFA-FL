# =============================================================================
# components.py — Map fuzz harnesses to their edk2 component / module path
# =============================================================================
#
# A "component" is the top-level edk2 package directory (e.g. SecurityPkg,
# MdeModulePkg, OvmfPkg, FatPkg, DeviceSecurityPkg, ...).
#
# Output files (written to InsightsExtractor/data/):
#   harness_components.csv   — flat table, one row per harness
#   harness_components.md    — grouped-by-component Markdown table
#
# Usage:
#   python3 -m InsightsExtractor.components            # write + print summary
#   python3 -m InsightsExtractor.components --print    # print only
# =============================================================================

import argparse
import csv
from collections import defaultdict
from pathlib import Path

from .config import DATA_DIR
from .discovery import discover_harnesses

CSV_PATH = DATA_DIR / "harness_components.csv"
MD_PATH  = DATA_DIR / "harness_components.md"

COLUMNS = ("Component", "Module", "Harness", "edk2 Source", "INF")


def build_rows():
    """Return list of dicts ordered by (component, module, harness)."""
    rows = []
    for name, info in discover_harnesses().items():
        edk2_rel = info["edk2_rel"]
        parts = Path(edk2_rel).parts
        component = parts[0] if parts else "(unknown)"
        module = "/".join(parts[1:]) if len(parts) > 1 else ""
        rows.append({
            "Component":   component,
            "Module":      module,
            "Harness":     name,
            "edk2 Source": f"edk2/{edk2_rel}",
            "INF":         info["inf_rel"],
        })
    rows.sort(key=lambda r: (r["Component"], r["Module"], r["Harness"]))
    return rows


def write_csv(rows, path: Path = CSV_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


def write_markdown(rows, path: Path = MD_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    by_component = defaultdict(list)
    for r in rows:
        by_component[r["Component"]].append(r)

    lines = ["# HBFA Harness → edk2 Component Map", ""]
    lines.append(f"Total harnesses: **{len(rows)}**  ")
    lines.append(f"Components covered: **{len(by_component)}**")
    lines.append("")

    for component in sorted(by_component):
        comp_rows = by_component[component]
        lines.append(f"## {component}  ({len(comp_rows)} harness"
                     f"{'es' if len(comp_rows) != 1 else ''})")
        lines.append("")
        lines.append("| Harness | Module | edk2 Source |")
        lines.append("|---|---|---|")
        for r in comp_rows:
            module = r["Module"] or "—"
            lines.append(f"| `{r['Harness']}` | {module} | `{r['edk2 Source']}` |")
        lines.append("")

    path.write_text("\n".join(lines))
    return path


def print_summary(rows):
    by_component = defaultdict(list)
    for r in rows:
        by_component[r["Component"]].append(r)

    print(f"Discovered {len(rows)} harness(es) across "
          f"{len(by_component)} component(s):\n")
    for component in sorted(by_component):
        comp_rows = by_component[component]
        print(f"  {component}  ({len(comp_rows)})")
        for r in comp_rows:
            mod = r["Module"] or "(root)"
            print(f"    - {r['Harness']:<45s}  {mod}")
        print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Map HBFA fuzz harnesses to edk2 components.")
    ap.add_argument("--print", action="store_true",
                    help="Only print the summary; do not write files.")
    args = ap.parse_args(argv)

    rows = build_rows()
    print_summary(rows)
    if not args.print:
        csv_path = write_csv(rows)
        md_path  = write_markdown(rows)
        print(f"[+] wrote {csv_path}")
        print(f"[+] wrote {md_path}")


if __name__ == "__main__":
    main()
