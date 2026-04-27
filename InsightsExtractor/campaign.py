# =============================================================================
# campaign.py — Launch + manage parallel AFL fuzzing
# =============================================================================

"""Run AFL across one or more harnesses with cores + duration controls."""

import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .config import AFL_OUTPUT_PREFIX


def _afl_fuzz_bin() -> str:
    """Locate afl-fuzz, preferring AFL_PATH then $PATH."""
    afl_path = os.environ.get("AFL_PATH")
    if afl_path and (Path(afl_path) / "afl-fuzz").is_file():
        return str(Path(afl_path) / "afl-fuzz")
    found = shutil.which("afl-fuzz")
    if not found:
        print("ERROR: afl-fuzz not found. Set AFL_PATH or add it to PATH.",
              file=sys.stderr)
        sys.exit(1)
    return found


def _afl_showmap_bin() -> str | None:
    afl_path = os.environ.get("AFL_PATH")
    if afl_path and (Path(afl_path) / "afl-showmap").is_file():
        return str(Path(afl_path) / "afl-showmap")
    return shutil.which("afl-showmap")


def _seed_survives(showmap: str, binary: Path, seed: Path,
                   timeout_ms: int, env: dict) -> bool:
    """Return True if ``seed`` causes ``binary`` to exit cleanly under afl-showmap.

    HBFA harnesses take the input file via ``argv[1]`` (the campaign
    launches them with ``-- <bin> @@``), so the seed must be passed as a
    positional argument here too — piping via stdin runs the binary
    against empty input and misses crash paths.
    """
    try:
        rc = subprocess.run(
            [showmap, "-m", "none", "-t", str(timeout_ms), "-q",
             "-o", "/dev/null", "--", str(binary), str(seed)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=env, timeout=max(10, timeout_ms / 1000 + 5),
        ).returncode
    except (subprocess.TimeoutExpired, OSError):
        return False
    return rc == 0


def _synthetic_seeds() -> list[tuple[str, bytes]]:
    """Battery of fallback seeds covering common 'safe' shapes.

    AFL rejects empty files in ``read_testcases``, so every entry here
    must be at least 1 byte.
    """
    out: list[tuple[str, bytes]] = [
        ("one_zero",   b"\x00"),
        ("zeros_16",   b"\x00" * 16),
        ("zeros_256",  b"\x00" * 256),
        ("zeros_4k",   b"\x00" * 4096),
        ("ones_256",   b"\xff" * 256),
        ("ascii_a",    b"A" * 64),
    ]
    for size in (16, 256, 4096):
        out.append((f"rand_{size}", os.urandom(size)))
    return out


def _stage_seeds(name: str, src_dir: Path, binary: Path,
                 timeout_ms: int) -> Path:
    """Stage seeds for AFL into a flat /tmp dir, dropping ones that crash.

    Always returns a non-empty seed dir. If every HBFA seed and every
    synthetic shape still crashes the binary (it shouldn't, given the
    relaxed ASan options in ``_afl_env``), an empty file is written so
    AFL has *something* to calibrate on; AFL's ``AFL_SKIP_CRASHES`` will
    let it advance past the dry run.
    """
    staged = Path(f"/tmp/afl_seed_{name}")
    if staged.exists():
        shutil.rmtree(staged, ignore_errors=True)
    staged.mkdir(parents=True, exist_ok=True)

    showmap = _afl_showmap_bin()
    env = _afl_env()

    kept = 0
    rejected = 0
    if src_dir.is_dir():
        for f in sorted(src_dir.rglob("*")):
            if not f.is_file():
                continue
            rel = f.relative_to(src_dir).as_posix().replace("/", "_")
            dst = staged / rel
            try:
                shutil.copyfile(f, dst)
            except OSError:
                continue
            if showmap and binary.is_file() and not _seed_survives(
                    showmap, binary, dst, timeout_ms, env):
                dst.unlink(missing_ok=True)
                rejected += 1
                continue
            kept += 1

    if kept == 0 and showmap and binary.is_file():
        # Try synthetic seeds of varying shapes; keep every one that
        # survives a dry-run (more is better — AFL randomly picks
        # starting cases). If none survive, write them all anyway:
        # AFL_SKIP_CRASHES=1 lets afl-fuzz proceed even when seeds crash,
        # but only if the input dir is non-empty with real (non-empty)
        # files, which is what we ensure here.
        for label, data in _synthetic_seeds():
            dst = staged / f"synthetic_{label}"
            dst.write_bytes(data)
            if _seed_survives(showmap, binary, dst, timeout_ms, env):
                kept += 1
        if kept > 0:
            print(f"  [!] {name}: HBFA seeds rejected ({rejected}); "
                  f"using {kept} synthetic seed(s)")
        else:
            # All synthetics crash too — keep them on disk anyway so AFL
            # at least has non-empty test cases. AFL_SKIP_CRASHES will
            # let it advance past calibration.
            kept = sum(1 for _ in staged.iterdir())
            print(f"  [!] {name}: every seed (HBFA + synthetic) crashes "
                  f"binary; keeping {kept} synthetic seed(s) anyway "
                  f"(AFL_SKIP_CRASHES=1 will proceed)")

    if kept == 0:
        # Truly nothing — write a 1-byte file so AFL has a non-empty
        # input. This is only reached if no afl-showmap is available.
        (staged / "fallback_seed").write_bytes(b"\x00")
        print(f"  [!] {name}: no validation tool; writing 1-byte fallback")

    return staged


def _afl_env(extra: dict = None) -> dict:
    env = os.environ.copy()
    env["AFL_SKIP_CPUFREQ"] = "1"
    env["AFL_NO_AFFINITY"] = "1"
    env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"
    env["AFL_AUTORESUME"] = "1"
    env["AFL_SKIP_CRASHES"] = "1"
    # ASan defaults per HBFA: AFL 2.52b's check_asan_opts() refuses to
    # run unless abort_on_error=1, so we keep that on and just disable
    # the noisy/non-deterministic checks. Inputs that trigger genuine
    # ASan findings on dry-run are real crashes and surface in
    # /tmp/afl_out_<name>/crashes/.
    env["ASAN_OPTIONS"] = (
        "abort_on_error=1:detect_leaks=0:detect_odr_violation=0:"
        "symbolize=0:allocator_may_return_null=1"
    )
    if extra:
        env.update(extra)
    return env


def cleanup_outputs(harnesses: dict) -> None:
    """Delete previous AFL output dirs so the campaign starts clean."""
    for info in harnesses.values():
        out = info["afl_output"]
        if out.is_dir():
            shutil.rmtree(out, ignore_errors=True)


# Glob patterns under /tmp produced by this tool (and afl_fuzz.sh) that
# accumulate across runs and bloat tmpfs if not cleared.
_TMP_STALE_GLOBS = (
    "/tmp/afl_out_*",
    "/tmp/afl_seed_*",
    "/tmp/cov_*.info",
    "/tmp/coverage_report_*",
    "/tmp/hbfa_report_*",
)


def cleanup_tmp() -> int:
    """Remove stale per-harness scratch under /tmp from prior runs.

    Returns the number of paths removed. Safe to call before any fuzz
    campaign; matches only the prefixes this tool (and afl_fuzz.sh)
    creates, so it will not touch unrelated files.
    """
    removed = 0
    for pat in _TMP_STALE_GLOBS:
        for p in glob.glob(pat):
            path = Path(p)
            try:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    path.unlink(missing_ok=True)
                removed += 1
            except OSError:
                pass
    return removed


def _tail_log(path: Path, n: int) -> list:
    """Return the last ``n`` non-empty lines of a log file (best-effort)."""
    try:
        data = path.read_bytes().decode("utf-8", errors="replace")
    except OSError:
        return []
    lines = [ln.rstrip() for ln in data.splitlines() if ln.strip()]
    return lines[-n:]


_FUZZER_STAT_KEYS = (
    "start_time", "last_update", "run_time",
    "execs_done", "execs_per_sec", "paths_total",
    "unique_crashes", "unique_hangs", "last_path", "last_crash",
)


def _read_fuzzer_stats(path: Path) -> dict:
    """Parse AFL's ``fuzzer_stats`` file into a dict (numeric values floats)."""
    out = {}
    try:
        for line in path.read_text(errors="replace").splitlines():
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if k in _FUZZER_STAT_KEYS:
                try:
                    out[k] = float(v)
                except ValueError:
                    out[k] = v
    except OSError:
        pass
    return out


def _aggregate_afl_stats(harnesses: dict) -> dict:
    """Sum/aggregate fuzzer_stats across every main+secondary instance.

    Returns a dict with totals across all live AFL output dirs:
      run_time_max  (s)   longest-running instance — closest to AFL's own clock
      execs_done    (sum) total executions
      execs_per_sec (sum) aggregate throughput
      paths_total   (sum) sum of paths across instances (overcounts shared finds)
      unique_crashes (sum)
      unique_hangs   (sum)
    """
    rt_max = 0.0
    execs = 0.0
    eps = 0.0
    paths = 0.0
    crashes = 0.0
    hangs = 0.0
    n = 0
    for info in harnesses.values():
        out = info.get("afl_output")
        if not out or not out.is_dir():
            continue
        for sub in out.iterdir():
            stats = _read_fuzzer_stats(sub / "fuzzer_stats")
            if not stats:
                continue
            n += 1
            # AFL 2.52b fuzzer_stats has no `run_time` key; derive from
            # last_update - start_time (AFL's own clock, not host wall-clock).
            rt = stats.get("run_time", 0.0) or 0.0
            if not rt:
                st = stats.get("start_time", 0.0) or 0.0
                lu = stats.get("last_update", 0.0) or 0.0
                if st and lu and lu >= st:
                    rt = lu - st
            rt_max = max(rt_max, rt)
            execs += stats.get("execs_done", 0.0) or 0.0
            eps += stats.get("execs_per_sec", 0.0) or 0.0
            paths += stats.get("paths_total", 0.0) or 0.0
            crashes += stats.get("unique_crashes", 0.0) or 0.0
            hangs += stats.get("unique_hangs", 0.0) or 0.0
    return {
        "instances": n,
        "run_time_max": rt_max,
        "execs_done": execs,
        "execs_per_sec": eps,
        "paths_total": paths,
        "unique_crashes": crashes,
        "unique_hangs": hangs,
    }


class FuzzCampaign:
    """Launch AFL master + secondaries for each harness, distributed over cores."""

    def __init__(self, harnesses: dict, total_cores: int, timeout_ms: int = 1000):
        self.harnesses = harnesses
        self.total_cores = max(1, total_cores)
        self.timeout_ms = timeout_ms
        self.processes = []   # list of (name, tag, log_path|None, Popen)
        self._stopped = False
        self._afl_bin = _afl_fuzz_bin()
        self._save_afl_logs = os.environ.get("INSIGHTS_AFL_SAVE_LOGS", "0") == "1"

    # ------------------------------------------------------------------
    def launch(self) -> None:
        n = len(self.harnesses)
        if n == 0:
            print("ERROR: no harnesses to fuzz.", file=sys.stderr)
            sys.exit(1)
        cores_per = max(1, self.total_cores // n)
        cores = self._available_cores()
        cidx = 0

        print(f"[campaign] harnesses={n} cores={self.total_cores} "
              f"cores/harness={cores_per} timeout={self.timeout_ms}ms")

        for name, info in self.harnesses.items():
            binary = info["binary_afl"]
            seed_src = info["seed_dir"]
            out_dir = info["afl_output"]
            if not binary.is_file():
                print(f"  SKIP {name}: AFL binary missing ({binary})")
                continue
            seed_dir = _stage_seeds(name, seed_src, binary, self.timeout_ms)
            out_dir.mkdir(parents=True, exist_ok=True)

            for i in range(cores_per):
                cpu = cores[cidx % len(cores)]
                cidx += 1
                role = "-M" if i == 0 else "-S"
                tag = "main" if i == 0 else f"sec{i:02d}"
                log_path = out_dir / f"afl_{tag}.log"
                cmd = [
                    "taskset", "-c", str(cpu),
                    self._afl_bin,
                    role, tag,
                    "-i", str(seed_dir),
                    "-o", str(out_dir),
                    "-m", "none",
                    "-t", str(self.timeout_ms),
                    "--", str(binary), "@@",
                ]
                if self._save_afl_logs:
                    log_fh = open(log_path, "wb")
                    proc = subprocess.Popen(
                        cmd, env=_afl_env(),
                        stdout=log_fh, stderr=subprocess.STDOUT,
                    )
                    log_fh.close()
                else:
                    log_path = None
                    proc = subprocess.Popen(
                        cmd, env=_afl_env(),
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                self.processes.append((name, tag, log_path, proc))
                print(f"  [+] {name} {tag} on CPU {cpu} (pid={proc.pid})")
                if i == 0 and cores_per > 1:
                    time.sleep(2)  # let master initialise output dir
        time.sleep(3)
        alive = [t for t in self.processes if t[3].poll() is None]
        dead = [t for t in self.processes if t[3].poll() is not None]
        print(f"[campaign] {len(alive)}/{len(self.processes)} fuzzers alive")
        for name, tag, log_path, proc in dead:
            rc = proc.returncode
            if log_path:
                tail = _tail_log(log_path, 8)
                print(f"  [-] DEAD {name} {tag} (exit={rc}) log={log_path}")
                for line in tail:
                    print(f"        {line}")
            else:
                print(f"  [-] DEAD {name} {tag} (exit={rc}) log=disabled")

    # ------------------------------------------------------------------
    def wait(self, duration_hours: float = None) -> None:
        # Duration is measured against AFL's own runtime (max run_time across
        # instances from fuzzer_stats), NOT host wall-clock. This way startup,
        # rebuilds, suspended processes, etc. don't eat into fuzzing budget.
        start = time.time()
        budget = duration_hours * 3600 if duration_hours else None
        beat = start + 15 * 60
        try:
            while True:
                alive = [t for t in self.processes if t[3].poll() is None]
                if not alive:
                    print("[campaign] all fuzzers exited")
                    return
                s = _aggregate_afl_stats(self.harnesses)
                afl_rt = int(s["run_time_max"])
                if budget and afl_rt >= budget:
                    print(f"[campaign] AFL runtime {afl_rt}s reached budget {int(budget)}s")
                    return
                if time.time() >= beat:
                    el = int(time.time() - start)
                    storage_bytes = 0
                    storage_roots = set()
                    for _info in self.harnesses.values():
                        _out = _info.get("afl_output")
                        if _out:
                            storage_roots.add(str(_out))
                    for pat in _TMP_STALE_GLOBS:
                        for p in glob.glob(pat):
                            storage_roots.add(p)
                    for p in storage_roots:
                        if os.path.isfile(p):
                            try:
                                storage_bytes += os.path.getsize(p)
                            except OSError:
                                pass
                            continue
                        for dirpath, _dirs, files in os.walk(p):
                            for f in files:
                                try:
                                    storage_bytes += os.path.getsize(os.path.join(dirpath, f))
                                except OSError:
                                    pass
                    if storage_bytes >= 1 << 30:
                        storage = f"{storage_bytes / (1 << 30):.2f}GiB"
                    elif storage_bytes >= 1 << 20:
                        storage = f"{storage_bytes / (1 << 20):.1f}MiB"
                    else:
                        storage = f"{storage_bytes / 1024:.0f}KiB"
                    print(f"[heartbeat] elapsed={el//3600:02d}h"
                          f"{(el%3600)//60:02d}m"
                          f" afl_rt={afl_rt//3600:02d}h{(afl_rt%3600)//60:02d}m"
                          f" alive={len(alive)}/{len(self.processes)}"
                          f" execs={int(s['execs_done']):,}"
                          f" eps={int(s['execs_per_sec']):,}"
                          f" paths={int(s['paths_total'])}"
                          f" crashes={int(s['unique_crashes'])}"
                          f" hangs={int(s['unique_hangs'])}"
                          f" storage={storage}",
                          flush=True)
                    beat += 15 * 60
                time.sleep(10)
        except KeyboardInterrupt:
            pass

    # ------------------------------------------------------------------
    def stop(self) -> None:
        if self._stopped:
            return
        self._stopped = True
        print("[campaign] stopping fuzzers...")
        for _, _, _, p in self.processes:
            if p.poll() is None:
                p.terminate()
        time.sleep(3)
        for _, _, _, p in self.processes:
            if p.poll() is None:
                p.kill()
                p.wait()
        print("[campaign] stopped")

    # ------------------------------------------------------------------
    @staticmethod
    def _available_cores() -> list:
        try:
            return sorted(os.sched_getaffinity(0))
        except AttributeError:
            return list(range(os.cpu_count() or 1))
