#!/usr/bin/env bash
set -euo pipefail

## DESCRIPTION:
##
## Build everything the `userspace` (ring 3) benchmarks need and run the ring 0
## vs ring 3 Criterion comparison on the CURRENT machine, recording a per-machine
## results table. Intended to be run on a real Linux host with KVM or mshv (not
## WSL), so the ring 3 overhead is measured on real hardware/hypervisors.
##
## It also builds `simpleguest-userspace`, which `just guests` does not yet build
## (see docs/userspace-ring3.md "Future work"), so the ring 3 benchmark binary is
## available.
##
## PRE-REQS (on the target machine, before running):
##   - rustup with the repo toolchain (rust-toolchain.toml pins it) and the
##     x86_64-hyperlight-none target available to `cargo hyperlight`
##   - just, cargo-hyperlight (the script installs cargo-hyperlight via `just guests`)
##   - a writable hypervisor device: /dev/kvm OR /dev/mshv
##   - the usual C-guest build deps (clang) for `just guests`
##
## WINDOWS / WHP: this bash script targets Linux (KVM/mshv). On Windows run the
## equivalent by hand in a developer shell:
##   just build release
##   just guests
##   pushd src/tests/rust_guests; cargo hyperlight build -p simpleguest --no-default-features -F userspace --profile=release; popd
##   copy src\tests\rust_guests\target\x86_64-hyperlight-none\release\simpleguest.exe ^
##        src\tests\rust_guests\bin\release\simpleguest-userspace.exe
##   $env:CARGO_TERM_COLOR="never"
##   cargo bench -p hyperlight-host --profile=release --features userspace -- "guest_calls/|sandboxes/|snapshots/|sample_workloads/24K" | Tee-Object raw.log
##   cargo bench -p hyperlight-host --profile=release --features userspace -- "guest_functions_with_large_parameters" | Tee-Object -Append raw.log
## then re-process raw.log on any machine with:  dev/run-userspace-benchmarks.sh --reduce raw.log
##
## USAGE:
##   dev/run-userspace-benchmarks.sh [--mode full|core|smoke] [--out DIR] [--measurement-time SECS]
##   dev/run-userspace-benchmarks.sh --reduce RAW_CRITERION_LOG
##
##   --mode full   (default) guest_calls + sandboxes + snapshots + 24K + large_parameters
##   --mode core   guest_calls + 24K + large_parameters (skips the slow sandbox/snapshot size sweep)
##   --mode smoke  guest_calls/call only, with --quick (fast end-to-end validation, NOT a real result)
##   --reduce FILE re-process a captured Criterion log into the medians/comparison tables and exit

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

MODE="full"
OUT_BASE="$REPO_ROOT/bench-results"
MEASUREMENT_TIME=""
REDUCE_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="${2:?--mode needs a value}"; shift 2 ;;
        --out) OUT_BASE="${2:?--out needs a value}"; shift 2 ;;
        --measurement-time) MEASUREMENT_TIME="${2:?--measurement-time needs a value}"; shift 2 ;;
        --reduce) REDUCE_FILE="${2:?--reduce needs a file}"; shift 2 ;;
        -h|--help) sed -n '3,40p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

log() { printf '\033[1;34m[bench]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[bench] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# --- Extract "<id>\t<median> <unit>" pairs from a raw Criterion log. ----------
# A benchmark id line is printed flush-left with no whitespace and no ':'
# (which excludes the "Benchmarking ...:" progress lines and the indented
# "time:"/stat lines). The median is the middle value of the "[lo mid hi]" range.
extract_medians() {
    awk '
        /^[!-~]+$/ && $0 !~ /:/ { id=$0; next }
        /time:/ && id != "" {
            b=index($0,"["); e=index($0,"]");
            inner=substr($0,b+1,e-b-1);
            n=split(inner,a," ");
            if (n>=4) printf "%s\t%s %s\n", id, a[3], a[4];
            id="";
        }
    ' "$1"
}

# --- Pair each ring 0 id with its /ring3 sibling and compute the Δ%. ----------
compare_rings() {
    awk -F'\t' '
        function to_ns(s,   v,u,a,n){
            n=split(s,a," "); v=a[1]; u=a[2];
            if (u=="ns") return v;
            if (u=="ms") return v*1000000;
            if (u=="s")  return v*1000000000;
            return v*1000;   # default: microseconds (µs)
        }
        { med[$1]=$2 }
        END{
            for (k in med) {
                if (k ~ /\/ring3$/) continue;
                r3=k "/ring3";
                if (r3 in med) {
                    a=to_ns(med[k]); b=to_ns(med[r3]);
                    d=(a>0)?(b-a)/a*100:0;
                    printf "%s\t%s\t%s\t%+.1f%%\n", k, med[k], med[r3], d;
                }
            }
        }
    ' "$1" | sort
}

reduce_log() {
    local raw="$1" outdir="$2"
    extract_medians "$raw" > "$outdir/medians.tsv"
    {
        printf 'benchmark\tring0\tring3\tdelta\n'
        compare_rings "$outdir/medians.tsv"
    } > "$outdir/comparison.tsv"
    log "Medians:    $outdir/medians.tsv ($(wc -l < "$outdir/medians.tsv") rows)"
    log "Comparison: $outdir/comparison.tsv"
    echo
    column -t -s $'\t' "$outdir/comparison.tsv"
}

# --- --reduce: just re-process an existing log and exit. ----------------------
if [[ -n "$REDUCE_FILE" ]]; then
    [[ -f "$REDUCE_FILE" ]] || die "no such file: $REDUCE_FILE"
    OUTDIR="$(dirname "$REDUCE_FILE")"
    reduce_log "$REDUCE_FILE" "$OUTDIR"
    exit 0
fi

# --- Detect the hypervisor (the host bench auto-selects at runtime). ----------
HYPERVISOR="none"
if [[ -w /dev/mshv ]]; then HYPERVISOR="mshv"
elif [[ -w /dev/kvm ]]; then HYPERVISOR="kvm"
fi
[[ "$HYPERVISOR" == "none" ]] && die "no writable /dev/kvm or /dev/mshv found; the benchmarks need a hypervisor"

TS="$(date +%Y%m%d-%H%M%S)"
OUTDIR="$OUT_BASE/$(hostname -s)-${HYPERVISOR}-${TS}"
mkdir -p "$OUTDIR"
RAW="$OUTDIR/raw.log"

# --- Record the machine environment alongside the results. --------------------
{
    echo "host:        $(hostname -f 2>/dev/null || hostname)"
    echo "date:        $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "hypervisor:  $HYPERVISOR"
    echo "kernel:      $(uname -srmo)"
    echo "cpu:         $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//' || echo unknown)"
    echo "cpus:        $(nproc)"
    echo "rustc:       $(rustc --version 2>/dev/null || echo unknown)"
    echo "git:         $(git rev-parse --short HEAD) ($(git rev-parse --abbrev-ref HEAD))"
    echo "mode:        $MODE"
} | tee "$OUTDIR/env.txt"
echo

# --- Build host, default guests, and the userspace ring 3 guest. --------------
log "Building host (release)..."
just build release

log "Building + moving guests (debug + release)..."
just guests

log "Building + deploying the userspace (ring 3) guest..."
( cd src/tests/rust_guests && cargo hyperlight build -p simpleguest --no-default-features -F userspace --profile=release )
cp src/tests/rust_guests/target/x86_64-hyperlight-none/release/simpleguest \
   src/tests/rust_guests/bin/release/simpleguest-userspace
log "Deployed simpleguest-userspace."

# --- Run the benchmarks. ------------------------------------------------------
export CARGO_TERM_COLOR=never
MT_ARGS=()
[[ -n "$MEASUREMENT_TIME" ]] && MT_ARGS=(--measurement-time "$MEASUREMENT_TIME")

run_bench() { # <criterion-filter-regex> [extra criterion args...]
    local filter="$1"; shift
    log "cargo bench -- '$filter' ${MT_ARGS[*]:-} $*"
    cargo bench -p hyperlight-host --profile=release --features userspace -- \
        "$filter" "${MT_ARGS[@]}" "$@" 2>&1 | tee -a "$RAW"
}

: > "$RAW"
case "$MODE" in
    full)
        run_bench 'guest_calls/|sandboxes/|snapshots/|sample_workloads/24K'
        run_bench 'guest_functions_with_large_parameters'
        ;;
    core)
        run_bench 'guest_calls/|sample_workloads/24K'
        run_bench 'guest_functions_with_large_parameters'
        ;;
    smoke)
        run_bench 'guest_calls/call/' --quick
        ;;
    *) die "unknown --mode: $MODE (expected full|core|smoke)" ;;
esac

# --- Reduce to the per-machine results tables. --------------------------------
echo
log "Raw Criterion output: $RAW"
reduce_log "$RAW" "$OUTDIR"
echo
log "Done. Results in: $OUTDIR"
[[ "$MODE" == "smoke" ]] && log "NOTE: --mode smoke is a fast validation run (--quick); do NOT record these as real results."
exit 0
