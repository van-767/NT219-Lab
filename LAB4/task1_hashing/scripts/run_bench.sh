#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# LAB4 performance evaluation (Linux).
# Required algorithms: SHA-256, SHA-512, SHA3-256, SHA3-512.
# Benchmark sizes: 1 MiB, 8 MiB, 50 MiB, 100 MiB.

EXE="./bin/linux/hashtool"
[[ -x "$EXE" ]] || { echo "ERROR: $EXE not found. cmake --build build -j" >&2; exit 1; }

mkdir -p logs/linux
N=30
BLOCK=1000

declare -a SIZES=("1MiB:1048576" "8MiB:8388608" "50MiB:52428800" "100MiB:104857600")

declare -a ALGOS=("sha256" "sha512" "sha3-256" "sha3-512")

run_bench() {
    local name="$1"; shift
    local start ts; start=$(date +%s); ts=$(date +%H:%M:%S)
    echo; echo "[$ts] >>> $name"; echo "    $*"
    "$@"
    local elapsed=$(( $(date +%s) - start ))
    printf "    done in %02d:%02d:%02d\n" \
        $((elapsed / 3600)) $(((elapsed % 3600) / 60)) $((elapsed % 60))
}

total_start=$(date +%s)
for alg in "${ALGOS[@]}"; do
    tag="${alg/-/_}"
    for s in "${SIZES[@]}"; do
        name="${s%%:*}"; bytes="${s##*:}"
        run_bench "$alg @ $name, block=$BLOCK" "$EXE" bench \
            --algo "$alg" --size "$bytes" --n "$N" --block "$BLOCK" \
            --log "logs/linux/${tag}_${name}.csv"
    done
done

total_elapsed=$(( $(date +%s) - total_start ))
printf "\n=============================================\n"
printf "TOTAL elapsed: %02d:%02d:%02d\n" \
    $((total_elapsed / 3600)) $(((total_elapsed % 3600) / 60)) $((total_elapsed % 60))
printf "Logs: %s/logs/linux/\n" "$(pwd)"
printf "=============================================\n"
