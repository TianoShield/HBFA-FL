# =============================================================================
# run_fuzz_campaign.py — CLI entry point
# =============================================================================

"""Orchestrate: build → fuzz → coverage → crashes → hbfa_metrics.xlsx."""

import argparse
import signal
import sys

from .builder import build_harnesses
from .campaign import FuzzCampaign, cleanup_outputs, cleanup_tmp
from .config import DATA_DIR, METRICS_XLSX
from .coverage import collect_all as collect_coverage
from .crashes import collect_all as collect_crashes
from .discovery import discover_harnesses
from .metrics import write_metrics


def _parse_args():
    p = argparse.ArgumentParser(
        description="Run AFL fuzzing across HBFA harnesses and produce "
                    "hbfa_metrics.xlsx with line+function coverage and crash counts.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 -m InsightsExtractor --list
  python3 -m InsightsExtractor --duration 1 --cores 8
  python3 -m InsightsExtractor --harness TestFmpAuthenticationLibPkcs7 --cores 4
  python3 -m InsightsExtractor --skip-fuzz                # only metrics from existing output
  python3 -m InsightsExtractor --skip-build --skip-fuzz   # just rebuild Excel
""")
    p.add_argument("--cores", type=int, default=4,
                   help="Total CPU cores to spread across harnesses (default: 4)")
    p.add_argument("--duration", type=float, default=1.0, metavar="HOURS",
                   help="Max fuzzing duration in hours (default: 1)")
    p.add_argument("--timeout", type=int, default=5000, metavar="MS",
                   help="AFL per-exec timeout in ms (default: 5000)")
    p.add_argument("--harness", nargs="+", metavar="NAME",
                   help="Specific harness name(s) to run (default: all)")
    p.add_argument("--resume", action="store_true",
                   help="Keep prior AFL output dirs (default: clean)")
    p.add_argument("--keep-tmp", action="store_true",
                   help="Keep stale /tmp scratch from prior runs "
                        "(default: wipe afl_out_*, afl_seed_*, cov_*.info, "
                        "coverage_report_*, hbfa_report_*)")
    p.add_argument("--skip-build",    action="store_true")
    p.add_argument("--skip-fuzz",     action="store_true")
    p.add_argument("--skip-coverage", action="store_true")
    p.add_argument("--skip-crashes",  action="store_true")
    p.add_argument("--list", dest="list_only", action="store_true",
                   help="List discovered harnesses and exit")
    return p.parse_args()


def main():
    args = _parse_args()
    all_harn = discover_harnesses()
    if not all_harn:
        print("ERROR: no harnesses found under HBFA/UefiHostFuzzTestCasePkg/TestCase",
              file=sys.stderr)
        sys.exit(1)

    if args.list_only:
        print(f"Discovered {len(all_harn)} harness(es):\n")
        for n in sorted(all_harn):
            print(f"  {n}")
            print(f"    inf:  {all_harn[n]['inf_rel']}")
            print(f"    edk2: {all_harn[n]['edk2_rel']}")
        return

    if args.harness:
        harn = {n: all_harn[n] for n in args.harness if n in all_harn}
        missing = [n for n in args.harness if n not in all_harn]
        for n in missing:
            print(f"WARNING: unknown harness '{n}'", file=sys.stderr)
        if not harn:
            print("ERROR: no valid harnesses selected.", file=sys.stderr)
            sys.exit(1)
    else:
        harn = all_harn

    print(f"\n=== HBFA fuzz campaign ===")
    print(f"  harnesses : {len(harn)}")
    print(f"  cores     : {args.cores}")
    print(f"  duration  : {args.duration}h")
    print(f"  timeout   : {args.timeout}ms")
    print()

    # 1. Build
    if not args.skip_build:
        build_harnesses(harn)

    # 2. Fuzz
    if not args.skip_fuzz:
        if not args.resume:
            cleanup_outputs(harn)
            if not args.keep_tmp:
                n = cleanup_tmp()
                if n:
                    print(f"[campaign] cleared {n} stale /tmp entr{'y' if n == 1 else 'ies'}")
        camp = FuzzCampaign(harn, args.cores, args.timeout)

        def _handler(signum, frame):
            print(f"\n[*] received signal {signum}, stopping...")
            camp.stop()
        signal.signal(signal.SIGINT,  _handler)
        signal.signal(signal.SIGTERM, _handler)

        camp.launch()
        camp.wait(args.duration)
        camp.stop()

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 3. Crashes
    crash_rows = [] if args.skip_crashes else collect_crashes(harn)

    # 4. Coverage
    cov_rows = [] if args.skip_coverage else collect_coverage(harn)

    # 5. Excel
    write_metrics(cov_rows, crash_rows)

    print(f"\n=== Done. Open {METRICS_XLSX} ===\n")


if __name__ == "__main__":
    main()
