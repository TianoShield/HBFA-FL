# =============================================================================
# builder.py — Build harnesses with both AFL and GCC5 toolchains
# =============================================================================

"""Invoke edk2 ``build`` for AFL (fuzzing) and GCC5 (coverage) toolchains."""

import os
import subprocess
import sys
from pathlib import Path

from .config import DEFAULT_ARCH, DEFAULT_TARGET, HBFA_DIR, HBFA_DSC, WORKSPACE


def _build_env() -> dict:
    env = os.environ.copy()
    env["WORKSPACE"] = str(WORKSPACE)
    if "PACKAGES_PATH" not in env:
        env["PACKAGES_PATH"] = f"{WORKSPACE}/edk2:{HBFA_DIR}"
    if "EDK_TOOLS_PATH" not in env:
        env["EDK_TOOLS_PATH"] = str(WORKSPACE / "edk2" / "BaseTools")
    return env


def build_harnesses(harnesses: dict, toolchains=("AFL", "GCC5")) -> None:
    """Build each harness with each toolchain. Aborts on failure."""
    env = _build_env()
    for tc in toolchains:
        print(f"\n[build] toolchain={tc}")
        for name, info in harnesses.items():
            inf_rel = info["inf_rel"]
            cmd = [
                "build",
                "-p", HBFA_DSC,
                "-m", inf_rel,
                "-a", DEFAULT_ARCH,
                "-b", DEFAULT_TARGET,
                "-t", tc,
            ]
            print(f"  [{tc}] {name}  ({inf_rel})")
            r = subprocess.run(cmd, cwd=str(HBFA_DIR), env=env)
            if r.returncode != 0:
                print(f"ERROR: build failed for {name} (toolchain={tc})",
                      file=sys.stderr)
                sys.exit(1)
