# =============================================================================
# crashes.py — Collect, dedupe and export AFL crashes
# =============================================================================

"""Walk AFL output, dedupe via ASan stack-trace fingerprint, save unique seeds."""

import csv
import os
import re
import shutil
import subprocess
from pathlib import Path

from .config import CRASH_SEED_DIR, CRASHES_CSV


_ASAN_FRAME_RE = re.compile(r"#\d+\s+\S+\s+in\s+(\S+)\s+(\S+):(\d+)")


def _list_crashes(afl_output: Path) -> list:
    """Return list of crash file paths under any */crashes subdir."""
    out = []
    if not afl_output.is_dir():
        return out
    for sub in afl_output.iterdir():
        cdir = sub / "crashes"
        if cdir.is_dir():
            for f in cdir.iterdir():
                if f.is_file() and f.name.startswith("id:"):
                    out.append(f)
    return out


def _run_for_asan(binary: Path, crash_file: Path, timeout_s: int = 15) -> str:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = (
        "detect_leaks=0:detect_odr_violation=0:abort_on_error=0:"
        "symbolize=1:allocator_may_return_null=1"
    )
    try:
        r = subprocess.run([str(binary), str(crash_file)],
                           env=env, timeout=timeout_s,
                           capture_output=True, text=True, errors="replace")
        return (r.stderr or "") + (r.stdout or "")
    except (subprocess.TimeoutExpired, OSError):
        return ""


def _fingerprint(asan_text: str) -> tuple:
    """Return (error_type, fingerprint_str) from ASan output."""
    em = re.search(r"ERROR: AddressSanitizer: (\S+)", asan_text)
    if not em:
        # AFL also catches plain SEGVs without ASan header
        if "SEGV" in asan_text or "signal" in asan_text.lower():
            err = "SEGV"
        elif not asan_text.strip():
            return ("no-output", "no-output")
        else:
            err = "unknown"
    else:
        err = em.group(1)
    head = re.split(r"\n(?:allocated|freed|previously allocated) by thread",
                    asan_text)[0]
    edk2_frames = []
    any_frames = []
    for m in _ASAN_FRAME_RE.finditer(head):
        func, fpath, line = m.group(1), m.group(2), m.group(3)
        any_frames.append((func, os.path.basename(fpath), line))
        if "/edk2/" in fpath:
            rel = fpath.split("/edk2/")[-1]
            edk2_frames.append((func, rel, line))
    frames = edk2_frames or any_frames
    if not frames:
        return (err, f"{err}|noframes")
    func, src, line = frames[0]
    return (err, f"{err}|{func}:{src}:{line}")


def collect_all(harnesses: dict) -> list:
    """Dedupe crashes per harness, copy unique seeds, return list of rows."""
    print(f"\n[crashes] gathering and deduplicating crashes...")
    if CRASH_SEED_DIR.exists():
        shutil.rmtree(CRASH_SEED_DIR)
    CRASH_SEED_DIR.mkdir(parents=True, exist_ok=True)

    rows = []
    for name, info in sorted(harnesses.items()):
        crashes = _list_crashes(info["afl_output"])
        binary  = info["binary_afl"]
        unique = {}    # fingerprint -> (error_type, seed_path)
        for c in crashes:
            asan = _run_for_asan(binary, c) if binary.is_file() else ""
            err, fp = _fingerprint(asan)
            if fp not in unique:
                unique[fp] = (err, c)
        # Copy unique seeds to data/crash_seeds/<harness>/
        outdir = CRASH_SEED_DIR / name
        outdir.mkdir(parents=True, exist_ok=True)
        for idx, (fp, (err, src)) in enumerate(sorted(unique.items())):
            dst = outdir / f"crash_{idx:03d}_{err}"
            try:
                shutil.copy2(src, dst)
            except OSError:
                pass

        rows.append({
            "harness":        name,
            "edk2_source":    info["edk2_rel"],
            "crashes_total":  len(crashes),
            "crashes_unique": len(unique),
            "error_types":    ",".join(sorted({e for e, _ in unique.values()})),
        })
        print(f"  {name}: {len(crashes)} raw -> {len(unique)} unique")

    CRASHES_CSV.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        with open(CRASHES_CSV, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"[crashes] wrote {CRASHES_CSV}")
    return rows
