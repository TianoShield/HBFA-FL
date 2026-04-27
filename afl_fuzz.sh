#!/usr/bin/env bash
# =============================================================================
# afl_fuzz.sh — Launch / stop AFL fuzzing in tmux and generate code coverage
#                for any HBFA test driver.
#
# Usage:
#   ./afl_fuzz.sh <HARNESS> start [CORES]
#   ./afl_fuzz.sh <HARNESS> stop
#   ./afl_fuzz.sh <HARNESS> status
#   ./afl_fuzz.sh <HARNESS> coverage [PORT]
#   ./afl_fuzz.sh <HARNESS> report   [PORT]
#
# <HARNESS> may be:
#   - the BASE_NAME of the test (e.g. TestFmpAuthenticationLibPkcs7)
#   - a path to the .inf file
#   - a directory under HBFA/UefiHostFuzzTestCasePkg/TestCase/
#
# Coverage is automatically scoped to the corresponding edk2 source directory.
# Example: TestFmpAuthenticationLibPkcs7 → edk2/SecurityPkg/Library/FmpAuthenticationLibPkcs7/
#
# tmux session is named afl-<HARNESS_NAME>.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Workspace root (must contain edk2/ and HBFA/) ──────────────────────────────
WORKSPACE="${WORKSPACE:-$SCRIPT_DIR}"
while [[ "$WORKSPACE" != "/" ]]; do
  [[ -d "$WORKSPACE/edk2" && -d "$WORKSPACE/HBFA" ]] && break
  WORKSPACE="$(dirname "$WORKSPACE")"
done
if [[ "$WORKSPACE" == "/" ]]; then
  echo "ERROR: cannot locate workspace (need edk2/ and HBFA/ siblings)" >&2
  exit 1
fi
export WORKSPACE

HBFA_PKG="UefiHostFuzzTestCasePkg"
TESTCASE_ROOT="$WORKSPACE/HBFA/$HBFA_PKG/TestCase"
SEED_ROOT="$WORKSPACE/HBFA/$HBFA_PKG/Seed"
BUILD_AFL_DIR="$WORKSPACE/Build/$HBFA_PKG/DEBUG_AFL/X64"
BUILD_GCC5_DIR="$WORKSPACE/Build/$HBFA_PKG/DEBUG_GCC5/X64"

DEFAULT_CORES=8
DEFAULT_COV_PORT=8000
DEFAULT_REPORT_PORT=8001
HBFA_REPORT_DIR="$WORKSPACE/HBFA/UefiHostTestTools/Report"

usage() {
  cat >&2 <<EOF
Usage: $0 <HARNESS> {start|stop|status|coverage} [ARGS]

  start [CORES]     Launch AFL parallel fuzzing in tmux (default ${DEFAULT_CORES} cores)
  stop              Kill AFL and tear down the tmux session
  status            Run afl-whatsup
  coverage [PORT]   Replay queue+crashes through GCC5 binary and serve lcov report
                    (default port ${DEFAULT_COV_PORT}; scoped to actual edk2 source)
  report   [PORT]   Run HBFA UefiHostTestTools/Report (crashes/hangs/summary HTML)
                    and serve it (default port ${DEFAULT_REPORT_PORT})

<HARNESS> may be a BASE_NAME (e.g. TestFmpAuthenticationLibPkcs7),
a path to the .inf, or a TestCase subdirectory.
EOF
  exit 1
}

[[ $# -ge 2 ]] || usage
HARNESS_ARG="$1"; shift
ACTION="$1"; shift

# ── Resolve harness → INF path + BASE_NAME + edk2 source path ──────────────────
resolve_harness() {
  local arg="$1" inf="" base

  if [[ -f "$arg" && "$arg" == *.inf ]]; then
    inf="$(cd "$(dirname "$arg")" && pwd)/$(basename "$arg")"
  elif [[ -d "$arg" ]]; then
    inf="$(find "$arg" -maxdepth 2 -name "Test*.inf" \
              ! -path "*/Override/*" ! -path "*/InstrumentHookLib*" \
              -print -quit)"
  else
    # Treat as BASE_NAME — search the whole TestCase tree
    inf="$(grep -rsl --include='Test*.inf' \
              -E "^[[:space:]]*BASE_NAME[[:space:]]*=[[:space:]]*${arg}\b" \
              "$TESTCASE_ROOT" | head -n1)"
  fi
  [[ -n "$inf" && -f "$inf" ]] || { echo "ERROR: cannot resolve harness '$arg'" >&2; exit 1; }

  base="$(awk '/^[[:space:]]*BASE_NAME/{print $3; exit}' "$inf" | tr -d '\r\n')"
  [[ -n "$base" ]] || base="$(basename "$inf" .inf)"

  local rel
  rel="${inf#$TESTCASE_ROOT/}"
  rel="$(dirname "$rel")"

  printf '%s\n%s\n%s\n' "$inf" "$base" "$rel"
}

mapfile -t _R < <(resolve_harness "$HARNESS_ARG")
INF_PATH="${_R[0]}"
HARNESS_NAME="${_R[1]}"
EDK2_REL="${_R[2]}"

# Harness → list of edk2/ source dirs that the harness actually exercises.
# The TestCase/ directory layout often does NOT match the real edk2 source
# under test (e.g. TestVirtio10Blk lives under TestCase/OvmfPkg/Virtio10BlkDxe
# but exercises OvmfPkg/Virtio10Dxe + OvmfPkg/VirtioBlkDxe + the PciCap
# libraries). When a harness is listed here, the *scoped* lcov report is
# extracted from ALL of these paths instead of the inferred single dir.
# Paths are space-separated, relative to edk2/.
declare -A SCOPE_MAP=(
  # Every Virtio harness links *stub* library classes (VirtioBlkStubLib /
  # VirtioPciDevice{,10}StubLib) instead of the real OvmfPkg drivers, so
  # the only real edk2 component their binary actually executes is the
  # shared queue helper VirtioLib. Anything else reports 0/0.
  [TestVirtioBlk]="OvmfPkg/Library/VirtioLib"
  [TestVirtioBlkReadWrite]="OvmfPkg/Library/VirtioLib"
  [TestVirtioPciDevice]="OvmfPkg/Library/VirtioLib"
  [TestVirtio10Blk]="OvmfPkg/Library/VirtioLib"
  [TestTcg2MeasureGptTable]="SecurityPkg/Library/DxeTpm2MeasureBootLib MdeModulePkg/Universal/Disk/PartitionDxe"
  [TestTcg2MeasurePeImage]="SecurityPkg/Library/DxeTpm2MeasureBootLib MdePkg/Library/BasePeCoffLib"
)
SCOPE_RELS=()
if [[ -n "${SCOPE_MAP[$HARNESS_NAME]:-}" ]]; then
  read -r -a SCOPE_RELS <<< "${SCOPE_MAP[$HARNESS_NAME]}"
else
  SCOPE_RELS=("$EDK2_REL")
fi
# Primary path used for display only.
EDK2_REL="${SCOPE_RELS[0]}"

BINARY_AFL="$BUILD_AFL_DIR/$HARNESS_NAME"
BINARY_GCC5="$BUILD_GCC5_DIR/$HARNESS_NAME"
# Default AFL output to /tmp (tmpfs, fast). Override with AFL_OUT_ROOT for
# very long campaigns that would exhaust tmpfs (e.g. AFL_OUT_ROOT=$WORKSPACE/Build/afl_runs).
AFL_OUT_ROOT="${AFL_OUT_ROOT:-/tmp}"
mkdir -p "$AFL_OUT_ROOT"
OUTPUT_DIR="$AFL_OUT_ROOT/afl_out_${HARNESS_NAME}"
COVERAGE_DIR="/tmp/coverage_report_${HARNESS_NAME}"
REPORT_DIR="/tmp/hbfa_report_${HARNESS_NAME}"
SESSION="afl-${HARNESS_NAME}"

# Harness → seed-dir mapping (from
# docs/src/harness/includedfuzzharnesses.md). The HBFA tree nests seed
# inputs under per-domain subdirectories that don't match the harness
# name, so resolution by harness name alone won't work. We always stage
# the resolved seeds into a flat /tmp dir because AFL requires files
# directly under its -i directory.
declare -A SEED_MAP=(
  [TestTpm2CommandLib]="TPM/Raw"
  [TestBmpSupportLib]="BMP/Raw"
  [TestPartition]="UDF/Raw/Partition"
  [TestUdf]="UDF/Raw/FileSystem"
  [TestFileName]="UDF/Raw/FileName"
  [TestPeiUsb]="USB/Raw"
  [TestUsb]="USB/Raw"
  [TestIdentifyAtaDevice]="Ata/Raw"
  [TestPeiGpt]="Gpt/Raw"
  [TestSignatureList]="SignatureList/Raw"
  [TestVariableSmm]="VariableSmm/Raw"
  [TestCapsulePei]="Capsule"
  [TestFmpAuthenticationLibPkcs7]="Capsule"
  [TestFmpAuthenticationLibRsa2048Sha256]="Capsule"
  [TestTcg2MeasureGptTable]="Gpt/Raw"
  [TestTcg2MeasurePeImage]="Capsule"
  [TestValidateTdxCfv]="TdxHob/Raw"
  [TestVirtioPciDevice]="Blk/Raw"
  [TestVirtio10Blk]="Blk/Raw"
  [TestVirtioBlk]="Blk/Raw"
  [TestVirtioBlkReadWrite]="Blk/Raw"
)

SEED_SRC=""
if [[ -n "${SEED_MAP[$HARNESS_NAME]:-}" ]]; then
  SEED_SRC="$SEED_ROOT/${SEED_MAP[$HARNESS_NAME]}"
fi
if [[ -z "$SEED_SRC" || ! -d "$SEED_SRC" ]]; then
  for cand in "$SEED_ROOT/$HARNESS_NAME" "$SEED_ROOT/${HARNESS_NAME#Test}"; do
    [[ -d "$cand" ]] && { SEED_SRC="$cand"; break; }
  done
fi
SEED_DIR="/tmp/afl_seed_${HARNESS_NAME}"

# ── Helpers ────────────────────────────────────────────────────────────────────
ensure_seeds() {
  rm -rf "$SEED_DIR"
  mkdir -p "$SEED_DIR"
  local copied=0
  if [[ -n "$SEED_SRC" && -d "$SEED_SRC" ]]; then
    while IFS= read -r -d '' f; do
      local rel name
      rel="${f#$SEED_SRC/}"
      name="${rel//\//_}"
      cp -f "$f" "$SEED_DIR/$name"
      copied=$((copied + 1))
    done < <(find "$SEED_SRC" -type f ! -name "README*" ! -name ".*" -print0)
  fi

  # Validate: AFL aborts at dry-run if every staged seed crashes the binary.
  # Try each staged seed with afl-showmap; remove any that crash.
  if (( copied > 0 )) && [[ -x "$BINARY_AFL" ]]; then
    local kept=0 dropped=0 tmpmap
    tmpmap="$(mktemp)"
    for f in "$SEED_DIR"/*; do
      [[ -f "$f" ]] || continue
      if ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0 \
         afl-showmap -m none -t 5000 -q -o "$tmpmap" -- "$BINARY_AFL" "$f" >/dev/null 2>&1; then
        kept=$((kept + 1))
      else
        echo "[!] dropping crashing seed: $(basename "$f")"
        rm -f "$f"
        dropped=$((dropped + 1))
      fi
    done
    rm -f "$tmpmap"
    copied=$kept
    (( dropped > 0 )) && echo "[+] kept $kept seed(s), dropped $dropped crashing seed(s)"
  fi

  if (( copied == 0 )); then
    echo "[+] No usable seeds — generating a small random seed in $SEED_DIR"
    head -c 64 /dev/urandom > "$SEED_DIR/default_seed"
  else
    echo "[+] Using $copied seed file(s) from $SEED_SRC"
  fi
}

kill_port() {
  local port="$1" pids
  pids=$(lsof -ti :"$port" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    echo "[+] Killing pids on :$port: $pids"
    echo "$pids" | xargs -r kill -9 || true
  fi
  return 0
}

print_banner() {
  echo "╔═══════════════════════════════════════════════════════════════"
  echo "║ Harness  : $HARNESS_NAME"
  echo "║ INF      : $INF_PATH"
  if (( ${#SCOPE_RELS[@]} > 1 )); then
    echo "║ edk2 src : (scoped)"
    for r in "${SCOPE_RELS[@]}"; do
      echo "║            edk2/$r"
    done
  else
    echo "║ edk2 src : edk2/$EDK2_REL"
  fi
  echo "║ AFL bin  : $BINARY_AFL"
  echo "║ GCC5 bin : $BINARY_GCC5"
  echo "║ Seeds    : $SEED_DIR"
  echo "║ Output   : $OUTPUT_DIR"
  echo "╚═══════════════════════════════════════════════════════════════"
}

# ── Commands ───────────────────────────────────────────────────────────────────
do_start() {
  local cores="${1:-$DEFAULT_CORES}"
  [[ -x "$BINARY_AFL" ]] || { echo "ERROR: missing AFL binary $BINARY_AFL  (build first)" >&2; exit 1; }
  ensure_seeds
  print_banner
  echo "[*] cores=$cores  session=$SESSION"

  if tmux has-session -t "=$SESSION" 2>/dev/null; then
    echo "Session '$SESSION' already running. Attach: tmux attach -t $SESSION" >&2
    exit 1
  fi

  mkdir -p "$OUTPUT_DIR"
  local afl_env="ASAN_OPTIONS=detect_leaks=0:detect_odr_violation=0:abort_on_error=1:symbolize=0 \
AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_AUTORESUME=1 AFL_SKIP_CRASHES=1"

  local main_cmd="$afl_env afl-fuzz -m none -t 5000 -i '$SEED_DIR' -o '$OUTPUT_DIR' -M main -- '$BINARY_AFL' @@"
  tmux new-session -d -s "$SESSION" -n "main" "$main_cmd"
  echo "[+] Launched master 'main'"
  sleep 3

  for ((i = 1; i < cores; i++)); do
    local sec; sec="$(printf 'sec%02d' "$i")"
    local sec_cmd="$afl_env afl-fuzz -m none -t 5000 -i '$SEED_DIR' -o '$OUTPUT_DIR' -S '$sec' -- '$BINARY_AFL' @@"
    tmux new-window -t "$SESSION" -n "$sec" "$sec_cmd"
    echo "[+] Launched secondary '$sec'"
  done

  echo
  echo "[*] tmux attach -t $SESSION"
  echo "[*] $0 $HARNESS_ARG status"
  echo "[*] $0 $HARNESS_ARG stop"
}

do_stop() {
  echo "[*] Stopping $SESSION..."
  local pids
  pids=$(pgrep -f "afl-fuzz.* ${OUTPUT_DIR}( |$)" 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    echo "[+] killing AFL pids: $pids"
    echo "$pids" | xargs -r kill -9 2>/dev/null || true
    sleep 1
  fi
  if tmux has-session -t "=$SESSION" 2>/dev/null; then
    tmux kill-session -t "=$SESSION"
    echo "[+] tmux session destroyed"
  fi

  local shm
  shm=$(ipcs -m 2>/dev/null | awk -v u="$(id -un)" '$3==u && $6==0 {print $2}' | head -200)
  if [[ -n "$shm" ]]; then
    echo "$shm" | xargs -r -n 1 ipcrm -m 2>/dev/null || true
    echo "[+] cleaned $(echo "$shm" | wc -l) orphan SHM"
  fi
}

do_status() {
  [[ -d "$OUTPUT_DIR" ]] || { echo "(no output dir $OUTPUT_DIR)"; exit 1; }
  echo "── tmux ──"
  tmux list-windows -t "=$SESSION" 2>/dev/null || echo "(no session)"
  echo
  echo "── afl-whatsup ──"
  afl-whatsup -s "$OUTPUT_DIR" 2>/dev/null || afl-whatsup "$OUTPUT_DIR" 2>/dev/null || true

  echo
  echo "── runtime (from fuzzer_stats) ──"
  local any=0 rt_max=0
  while IFS= read -r -d '' stats; do
    any=1
    local inst rt start_ts last_ts h m
    inst="$(basename "$(dirname "$stats")")"
    start_ts="$(awk -F: '$1 ~ /^[[:space:]]*start_time[[:space:]]*$/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$stats")"
    last_ts="$(awk -F: '$1 ~ /^[[:space:]]*last_update[[:space:]]*$/ {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$stats")"
    if [[ "$start_ts" =~ ^[0-9]+$ && "$last_ts" =~ ^[0-9]+$ && "$last_ts" -ge "$start_ts" ]]; then
      rt=$((last_ts - start_ts))
    else
      rt=0
    fi
    (( rt > rt_max )) && rt_max=$rt
    h=$((rt / 3600))
    m=$(((rt % 3600) / 60))
    printf '  %-8s  %02dh%02dm (%ss)\n' "$inst" "$h" "$m" "$rt"
  done < <(find "$OUTPUT_DIR" -mindepth 2 -maxdepth 2 -type f -name fuzzer_stats -print0 2>/dev/null)

  if (( any == 0 )); then
    echo "  (no fuzzer_stats found yet)"
  else
    printf '  %-8s  %02dh%02dm (%ss)\n' "max" "$((rt_max / 3600))" "$(((rt_max % 3600) / 60))" "$rt_max"
  fi
}

do_coverage() {
  local port="${1:-$DEFAULT_COV_PORT}"
  [[ -x "$BINARY_GCC5" ]] || { echo "ERROR: missing GCC5 binary $BINARY_GCC5" >&2; exit 1; }
  print_banner
  echo "[*] port=$port"

  # Replay every queue + crashes dir we can find (else fall back to seeds)
  local replay_dirs=()
  if [[ -d "$OUTPUT_DIR" ]]; then
    while IFS= read -r d; do replay_dirs+=("$d"); done < <(find "$OUTPUT_DIR" -mindepth 2 -maxdepth 2 -type d \( -name queue -o -name crashes \))
  fi
  if [[ ${#replay_dirs[@]} -eq 0 && -d "$SEED_DIR" ]]; then
    replay_dirs+=("$SEED_DIR")
  fi
  if [[ ${#replay_dirs[@]} -eq 0 ]]; then
    echo "ERROR: no queue/crashes/seeds to replay" >&2; exit 1
  fi

  echo "[*] cleaning previous gcda files"
  find "$BUILD_GCC5_DIR" -name "*.gcda" -delete 2>/dev/null || true

  for d in "${replay_dirs[@]}"; do
    local n; n=$(find "$d" -maxdepth 1 -type f | wc -l)
    echo "[*] replaying $n files from $d"
    find "$d" -maxdepth 1 -type f ! -name "README*" ! -name ".*" -print0 |
      xargs -0 -n1 -I{} timeout 15 "$BINARY_GCC5" "{}" >/dev/null 2>&1 || true
  done

  rm -rf "$COVERAGE_DIR"
  mkdir -p "$COVERAGE_DIR"
  local raw="$COVERAGE_DIR/coverage.raw.info"
  local full="$COVERAGE_DIR/coverage.full.info"
  local scoped="$COVERAGE_DIR/coverage.scoped.info"

  echo "[*] running lcov capture"
  lcov --capture --directory "$BUILD_GCC5_DIR" --output-file "$raw" --quiet \
       --rc lcov_branch_coverage=0

  # Full report: every source file linked into this binary, but drop
  # system headers / build-tool noise so navigation is sensible.
  lcov --remove "$raw" \
       '/usr/*' '*/BaseTools/*' '*/HBFA/UefiInstrumentTestPkg/*' \
       '*/HBFA/UefiHostFuzzTestPkg/*' '*/HBFA/UefiHostTestPkg/*' \
       --output-file "$full" --quiet || cp "$raw" "$full"

  # Scoped report: every edk2/ dir the harness actually exercises (see
  # SCOPE_MAP at the top of this script). Pass each as its own --extract
  # pattern; lcov ORs them.
  local scope_patterns=()
  for rel in "${SCOPE_RELS[@]}"; do
    scope_patterns+=("*/edk2/$rel/*")
  done
  lcov --extract "$full" "${scope_patterns[@]}" \
       --output-file "$scoped" --quiet || cp "$full" "$scoped"

  echo
  echo "── Summary (full — every source file in binary) ──"
  lcov --summary "$full" 2>&1 | grep -E 'lines\.\.\.|functions\.\.\.' || true
  if (( ${#SCOPE_RELS[@]} > 1 )); then
    echo "── Summary (scoped to ${#SCOPE_RELS[@]} edk2 dirs: $(IFS=,; echo "${SCOPE_RELS[*]}")) ──"
  else
    echo "── Summary (scoped to edk2/$EDK2_REL) ──"
  fi
  lcov --summary "$scoped" 2>&1 | grep -E 'lines\.\.\.|functions\.\.\.' || true
  echo

  local scope_title
  if (( ${#SCOPE_RELS[@]} > 1 )); then
    scope_title="$HARNESS_NAME → $(IFS=,; echo "${SCOPE_RELS[*]}")"
  else
    scope_title="$HARNESS_NAME → edk2/$EDK2_REL"
  fi
  genhtml "$full"   --output-directory "$COVERAGE_DIR/html/full"   --quiet \
          --title "$HARNESS_NAME — all files in binary" --prefix "$WORKSPACE" || true
  genhtml "$scoped" --output-directory "$COVERAGE_DIR/html/scoped" --quiet \
          --title "$scope_title" --prefix "$WORKSPACE" || true

  cat > "$COVERAGE_DIR/html/index.html" <<HTML
<!doctype html><meta charset="utf-8">
<title>${HARNESS_NAME} coverage</title>
<style>body{font-family:sans-serif;margin:2em;max-width:48em}
li{margin:.5em 0}code{background:#eee;padding:.1em .3em;border-radius:3px}</style>
<h1>${HARNESS_NAME}</h1>
<p>edk2 source under test: <code>edk2/${EDK2_REL}</code></p>
<ul>
  <li><a href="full/index.html"><b>Full coverage</b></a> — every source file
      linked into the binary (browse all components touched).</li>
  <li><a href="scoped/index.html"><b>Scoped coverage</b></a> — only
      <code>edk2/${EDK2_REL}/</code>.</li>
</ul>
HTML

  echo "[*] HTML report at $COVERAGE_DIR/html"
  if [[ -d "$COVERAGE_DIR/html" ]]; then
    kill_port "$port"
    echo "[*] Serving on http://localhost:$port  (Ctrl-C to stop)"
    cd "$COVERAGE_DIR/html"
    exec python3 -m http.server "$port"
  fi
}

do_report() {
  local port="${1:-$DEFAULT_REPORT_PORT}"
  [[ -x "$BINARY_GCC5" ]] || { echo "ERROR: missing GCC5 binary $BINARY_GCC5" >&2; exit 1; }
  [[ -d "$HBFA_REPORT_DIR" ]] || { echo "ERROR: missing $HBFA_REPORT_DIR" >&2; exit 1; }

  # HBFA ReportMain wants an AFL output dir with fuzzer_stats + queue/
  # at the root. In parallel mode we have main/ + secNN/; prefer any dir
  # that has fuzzer_stats, otherwise fall back to whichever has a queue/.
  local result=""
  for cand in "$OUTPUT_DIR/main" "$OUTPUT_DIR"/sec* "$OUTPUT_DIR"; do
    [[ -d "$cand" && -f "$cand/fuzzer_stats" ]] && { result="$cand"; break; }
  done
  if [[ -z "$result" ]]; then
    for cand in "$OUTPUT_DIR/main" "$OUTPUT_DIR"/sec* "$OUTPUT_DIR"; do
      [[ -d "$cand/queue" ]] && { result="$cand"; break; }
    done
  fi
  [[ -n "$result" ]] || { echo "ERROR: no AFL output under $OUTPUT_DIR (run start first)" >&2; exit 1; }

  # Synthesize a minimal fuzzer_stats so ReportMain.py can run on a stopped fuzzer.
  if [[ ! -f "$result/fuzzer_stats" ]]; then
    echo "[!] $result/fuzzer_stats missing — synthesizing stub for offline report"
    {
      echo "start_time        : 0"
      echo "last_update       : 0"
      echo "fuzzer_pid        : 0"
      echo "cycles_done       : 0"
      echo "execs_done        : $(find "$result/queue" -maxdepth 1 -type f | wc -l)"
      echo "execs_per_sec     : 0"
      echo "paths_total       : $(find "$result/queue" -maxdepth 1 -type f | wc -l)"
      echo "unique_crashes    : $(find "$result/crashes" -maxdepth 1 -type f ! -name 'README*' 2>/dev/null | wc -l)"
      echo "unique_hangs      : $(find "$result/hangs"   -maxdepth 1 -type f ! -name 'README*' 2>/dev/null | wc -l)"
    } > "$result/fuzzer_stats"
  fi

  print_banner
  echo "[*] HBFA result : $result"
  echo "[*] report dir  : $REPORT_DIR"
  echo "[*] port        : $port"

  rm -rf "$REPORT_DIR"
  mkdir -p "$REPORT_DIR"

  ( cd "$HBFA_REPORT_DIR" && \
    python3 ReportMain.py -e "$BINARY_GCC5" -i "$result" -r "$REPORT_DIR" -t afl ) || {
      echo "ERROR: ReportMain.py failed" >&2; exit 1; }

  local html_root="$REPORT_DIR/DebugReport"
  [[ -d "$html_root" ]] || { echo "ERROR: report not produced at $html_root" >&2; exit 1; }

  local landing=""
  for f in GdbSummaryReport.html SanitizerSummaryReport.html IndexCrashes.html IndexHangs.html; do
    [[ -f "$html_root/$f" ]] && { landing="$f"; break; }
  done

  echo "[*] HBFA report at $html_root"
  kill_port "$port"
  echo "[*] Serving on http://localhost:$port/${landing}  (Ctrl-C to stop)"
  cd "$html_root"
  exec python3 -m http.server "$port"
}

case "$ACTION" in
  start)    do_start    "${1:-$DEFAULT_CORES}"      ;;
  stop)     do_stop                                 ;;
  status)   do_status                               ;;
  coverage) do_coverage "${1:-$DEFAULT_COV_PORT}"   ;;
  report)   do_report   "${1:-$DEFAULT_REPORT_PORT}";;
  *)        usage                                   ;;
esac
