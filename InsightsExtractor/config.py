# =============================================================================
# config.py — Workspace discovery and shared paths
# =============================================================================

"""Locate workspace, define HBFA package paths and output locations."""

import os
import sys
from pathlib import Path

INSIGHTS_DIR = Path(__file__).resolve().parent

# WORKSPACE is the directory containing both edk2/ and HBFA/
_env_ws = os.environ.get("WORKSPACE")
if _env_ws and Path(_env_ws).is_dir():
    WORKSPACE = Path(_env_ws).resolve()
else:
    WORKSPACE = INSIGHTS_DIR.parent

if not (WORKSPACE / "edk2").is_dir() or not (WORKSPACE / "HBFA").is_dir():
    print(f"ERROR: WORKSPACE={WORKSPACE} must contain edk2/ and HBFA/. "
          "Set the WORKSPACE env var.", file=sys.stderr)
    sys.exit(1)

# HBFA layout
HBFA_DIR        = WORKSPACE / "HBFA"
HBFA_PKG_NAME   = "UefiHostFuzzTestCasePkg"
HBFA_PKG_DIR    = HBFA_DIR / HBFA_PKG_NAME
TESTCASE_ROOT   = HBFA_PKG_DIR / "TestCase"
SEED_ROOT       = HBFA_PKG_DIR / "Seed"
HBFA_DSC        = f"{HBFA_PKG_NAME}/{HBFA_PKG_NAME}.dsc"

# Build outputs (relative to WORKSPACE/Build/<pkg>/<TARGET_TOOLCHAIN>/X64)
BUILD_ROOT      = WORKSPACE / "Build" / HBFA_PKG_NAME
BUILD_AFL_DIR   = BUILD_ROOT / "DEBUG_AFL" / "X64"
BUILD_GCC5_DIR  = BUILD_ROOT / "DEBUG_GCC5" / "X64"

# AFL output dir prefix.
# Always use /tmp for AFL output directories.
AFL_OUTPUT_PREFIX = "/tmp/afl_out_"

# Reports
DATA_DIR        = INSIGHTS_DIR / "data"
METRICS_XLSX    = DATA_DIR / "hbfa_metrics.xlsx"
COVERAGE_CSV    = DATA_DIR / "coverage_report.csv"
CRASHES_CSV     = DATA_DIR / "crash_report.csv"
CRASH_SEED_DIR  = DATA_DIR / "crash_seeds"

# edk2 source
EDK2_DIR        = WORKSPACE / "edk2"

# Build invocation
DEFAULT_ARCH    = "X64"
DEFAULT_TARGET  = "DEBUG"
