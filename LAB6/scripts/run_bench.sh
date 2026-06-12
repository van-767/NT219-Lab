#!/usr/bin/env bash
# Auto-run benchmark Lab 6 (Linux / Bash).
set -euo pipefail
cd "$(dirname "$0")/.."

MLDSA="./bin/linux/MLDSA"
MLKEM="./bin/linux/MLKEM"
for e in "$MLDSA" "$MLKEM"; do
    [[ -x "$e" ]] || { echo "ERROR: $e not found. cmake --build build -j" >&2; exit 1; }
done

mkdir -p logs/linux
N=30
BLOCK=1000

run_bench() {
    local name="$1"; shift
    local start ts
    start=$(date +%s); ts=$(date +%H:%M:%S)
    echo; echo "[$ts] >>> $name"
    echo "    $*"
    "$@"
    printf "    done in %02d:%02d:%02d\n" \
        $(( ($(date +%s) - start) / 3600 )) \
        $(( (($(date +%s) - start) % 3600) / 60 )) \
        $(( ($(date +%s) - start) % 60 ))
}

total_start=$(date +%s)

declare -a SIZES=("1KiB:1024" "16KiB:16384" "1MiB:1048576" "8MiB:8388608")

# ML-DSA-44 + 65
for alg in mldsa-44 mldsa-65; do
    tag="${alg#mldsa-}"
    run_bench "ML-DSA-${tag} keygen" "$MLDSA" bench --op keygen --algo $alg --n $N --block $BLOCK --log "logs/linux/mldsa_${tag}_keygen.csv"
    for s in "${SIZES[@]}"; do
        name="${s%%:*}"; bytes="${s##*:}"
        run_bench "ML-DSA-${tag} sign $name"   "$MLDSA" bench --op sign   --algo $alg --n $N --block $BLOCK --size $bytes --log "logs/linux/mldsa_${tag}_sign_$name.csv"
        run_bench "ML-DSA-${tag} verify $name" "$MLDSA" bench --op verify --algo $alg --n $N --block $BLOCK --size $bytes --log "logs/linux/mldsa_${tag}_verify_$name.csv"
    done
done

# ML-KEM-512 / 768 / 1024
for alg in mlkem-512 mlkem-768 mlkem-1024; do
    tag="${alg#mlkem-}"
    run_bench "ML-KEM-${tag} keygen" "$MLKEM" bench --op keygen --algo $alg --n $N --block $BLOCK --log "logs/linux/mlkem_${tag}_keygen.csv"
    run_bench "ML-KEM-${tag} encaps" "$MLKEM" bench --op encaps --algo $alg --n $N --block $BLOCK --log "logs/linux/mlkem_${tag}_encaps.csv"
    run_bench "ML-KEM-${tag} decaps" "$MLKEM" bench --op decaps --algo $alg --n $N --block $BLOCK --log "logs/linux/mlkem_${tag}_decaps.csv"
done

total_elapsed=$(( $(date +%s) - total_start ))
printf "\n=============================================\n"
printf "TOTAL elapsed: %02d:%02d:%02d\n" \
    $((total_elapsed / 3600)) $(((total_elapsed % 3600) / 60)) $((total_elapsed % 60))
printf "Logs o: %s/logs/linux/\n" "$(pwd)"
printf "=============================================\n"
