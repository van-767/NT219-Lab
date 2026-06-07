#!/usr/bin/env bash
# Auto-run toan bo benchmark cho Lab 5 tren Linux.
# Spec literal: n=30 rounds, block=1000 ops, warm-up 1s.
# Cach chay:
#   chmod +x scripts/run_bench.sh
#   ./scripts/run_bench.sh

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

ecdsa="./bin/linux/ECDSA"
rsapss="./bin/linux/RSAPSS"

for exe in "$ecdsa" "$rsapss"; do
    if [[ ! -x "$exe" ]]; then
        echo "ERROR: $exe not found or not executable. Build truoc: cmake --build build -j" >&2
        exit 1
    fi
done

mkdir -p logs/linux

N=30
BLOCK=1000
SIZES=(
    "1KiB:1024"
    "16KiB:16384"
    "1MiB:1048576"
    "8MiB:8388608"
)

run_bench() {
    local name="$1"
    shift
    local exe="$1"
    shift

    local start end elapsed
    start="$(date +%s)"
    printf '\n[%s] >>> %s\n' "$(date +%H:%M:%S)" "$name"
    printf '    %s' "$exe"
    for arg in "$@"; do
        printf ' %q' "$arg"
    done
    printf '\n'
    "$exe" "$@"
    end="$(date +%s)"
    elapsed=$((end - start))
    printf '    done in %02d:%02d:%02d\n' $((elapsed / 3600)) $(((elapsed % 3600) / 60)) $((elapsed % 60))
}

total_start="$(date +%s)"

# ---------- ECDSA P-256 (required) ----------
run_bench "ECDSA-P256 keygen" "$ecdsa" \
    bench --op keygen --algo ecdsa-p256 --n "$N" --block "$BLOCK" \
    --log logs/linux/ecdsa_p256_keygen.csv
for item in "${SIZES[@]}"; do
    name="${item%%:*}"
    bytes="${item##*:}"
    run_bench "ECDSA-P256 sign ${name}" "$ecdsa" \
        bench --op sign --algo ecdsa-p256 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/ecdsa_p256_sign_${name}.csv"
    run_bench "ECDSA-P256 verify ${name}" "$ecdsa" \
        bench --op verify --algo ecdsa-p256 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/ecdsa_p256_verify_${name}.csv"
done

# ---------- ECDSA P-384 (optional, +5 spec) ----------
run_bench "ECDSA-P384 keygen" "$ecdsa" \
    bench --op keygen --algo ecdsa-p384 --n "$N" --block "$BLOCK" \
    --log logs/linux/ecdsa_p384_keygen.csv
for item in "${SIZES[@]}"; do
    name="${item%%:*}"
    bytes="${item##*:}"
    run_bench "ECDSA-P384 sign ${name}" "$ecdsa" \
        bench --op sign --algo ecdsa-p384 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/ecdsa_p384_sign_${name}.csv"
    run_bench "ECDSA-P384 verify ${name}" "$ecdsa" \
        bench --op verify --algo ecdsa-p384 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/ecdsa_p384_verify_${name}.csv"
done

# ---------- RSA-PSS 3072 (required) ----------
run_bench "RSA-PSS-3072 keygen" "$rsapss" \
    bench --op keygen --bits 3072 --n "$N" --block "$BLOCK" \
    --log logs/linux/rsapss_3072_keygen.csv
for item in "${SIZES[@]}"; do
    name="${item%%:*}"
    bytes="${item##*:}"
    run_bench "RSA-PSS-3072 sign ${name}" "$rsapss" \
        bench --op sign --bits 3072 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/rsapss_3072_sign_${name}.csv"
    run_bench "RSA-PSS-3072 verify ${name}" "$rsapss" \
        bench --op verify --bits 3072 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/rsapss_3072_verify_${name}.csv"
done

# ---------- RSA-PSS 4096 (compare) ----------
run_bench "RSA-PSS-4096 keygen" "$rsapss" \
    bench --op keygen --bits 4096 --n "$N" --block "$BLOCK" \
    --log logs/linux/rsapss_4096_keygen.csv
for item in "${SIZES[@]}"; do
    name="${item%%:*}"
    bytes="${item##*:}"
    run_bench "RSA-PSS-4096 sign ${name}" "$rsapss" \
        bench --op sign --bits 4096 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/rsapss_4096_sign_${name}.csv"
    run_bench "RSA-PSS-4096 verify ${name}" "$rsapss" \
        bench --op verify --bits 4096 --n "$N" --block "$BLOCK" --size "$bytes" \
        --log "logs/linux/rsapss_4096_verify_${name}.csv"
done

total_end="$(date +%s)"
total_elapsed=$((total_end - total_start))
printf '\n=============================================\n'
printf 'TOTAL elapsed: %02d:%02d:%02d\n' $((total_elapsed / 3600)) $(((total_elapsed % 3600) / 60)) $((total_elapsed % 60))
printf 'Logs o: %s/logs/linux/\n' "$root"
printf '=============================================\n'
