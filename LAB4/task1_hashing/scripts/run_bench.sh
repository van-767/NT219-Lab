#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

EXE="./bin/linux/hashtool"
[[ -x "$EXE" ]] || { echo "ERROR: $EXE not found. cmake --build build -j" >&2; exit 1; }

mkdir -p logs/linux
N=30; BLOCK=1000

declare -a SIZES=("1KiB:1024" "64KiB:65536" "1MiB:1048576" "100MiB:104857600")
declare -a ALGOS=("sha256" "sha512" "sha3-256" "sha3-512")

run_bench() {
    local name="$1"; shift
    local start ts; start=$(date +%s); ts=$(date +%H:%M:%S)
    echo; echo "[$ts] >>> $name"; echo "    $*"
    "$@"
    printf "    done in %02d:%02d:%02d\n" \
        $(( ($(date +%s) - start) / 3600 )) \
        $(( (($(date +%s) - start) % 3600) / 60 )) \
        $(( ($(date +%s) - start) % 60 ))
}

total_start=$(date +%s)
for alg in "${ALGOS[@]}"; do
    tag="${alg/-/_}"
    for s in "${SIZES[@]}"; do
        name="${s%%:*}"; bytes="${s##*:}"
        run_bench "$alg @ $name" "$EXE" bench --algo $alg --size $bytes --n $N --block $BLOCK \
            --log "logs/linux/${tag}_${name}.csv"
    done
done

total_elapsed=$(( $(date +%s) - total_start ))
printf "\n=============================================\n"
printf "TOTAL elapsed: %02d:%02d:%02d\n" \
    $((total_elapsed / 3600)) $(((total_elapsed % 3600) / 60)) $((total_elapsed % 60))
printf "Logs o: %s/logs/linux/\n" "$(pwd)"
printf "=============================================\n"
