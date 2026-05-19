#!/usr/bin/env bash
# Auto-run toàn bộ benchmark cho Lab 3 (Linux / Bash).
# Đúng spec: block=1000 cho mọi op. Tổng thời gian dự kiến 6-8 giờ.
# Cách chạy:  chmod +x scripts/run_bench.sh && ./scripts/run_bench.sh

set -euo pipefail
cd "$(dirname "$0")/.."

EXE="./bin/linux/rsatool"
if [[ ! -x "$EXE" ]]; then
    echo "ERROR: $EXE not found. Build trước: cmake --build build -j" >&2
    exit 1
fi

mkdir -p logs/linux

# n = 30 sample (spec: 30..100), block = 1000 ops/block (spec literal).
N=30
BLOCK=1000

run_bench() {
    local name="$1"; shift
    local start ts
    start=$(date +%s)
    ts=$(date +%H:%M:%S)
    echo
    echo "[$ts] >>> $name"
    echo "    $EXE $*"
    "$EXE" "$@"
    printf "    done in %02d:%02d:%02d\n" \
        $(( ($(date +%s) - start) / 3600 )) \
        $(( (($(date +%s) - start) % 3600) / 60 )) \
        $(( ($(date +%s) - start) % 60 ))
}

total_start=$(date +%s)

# ---------- RSA (Section 5.1) ----------
run_bench "RSA keygen 3072"  bench --op keygen --bits 3072 --n $N --block $BLOCK --log logs/linux/keygen_3072.csv
run_bench "RSA keygen 4096"  bench --op keygen --bits 4096 --n $N --block $BLOCK --log logs/linux/keygen_4096.csv
run_bench "RSA encrypt 3072" bench --op enc    --bits 3072 --n $N --block $BLOCK --log logs/linux/enc_3072.csv
run_bench "RSA encrypt 4096" bench --op enc    --bits 4096 --n $N --block $BLOCK --log logs/linux/enc_4096.csv
run_bench "RSA decrypt 3072" bench --op dec    --bits 3072 --n $N --block $BLOCK --log logs/linux/dec_3072.csv
run_bench "RSA decrypt 4096" bench --op dec    --bits 4096 --n $N --block $BLOCK --log logs/linux/dec_4096.csv

# ---------- Hybrid Mode / AES-GCM throughput (Section 5.2) ----------
declare -a SIZES=(
    "1KiB:1024"
    "4KiB:4096"
    "16KiB:16384"
    "256KiB:262144"
    "1MiB:1048576"
    "8MiB:8388608"
)
for s in "${SIZES[@]}"; do
    name="${s%%:*}"
    bytes="${s##*:}"
    run_bench "AES-GCM encrypt $name" bench --op gcm_enc --n $N --block $BLOCK --size "$bytes" --log "logs/linux/gcm_enc_$name.csv"
    run_bench "AES-GCM decrypt $name" bench --op gcm_dec --n $N --block $BLOCK --size "$bytes" --log "logs/linux/gcm_dec_$name.csv"
done

total_elapsed=$(( $(date +%s) - total_start ))
printf "\n=============================================\n"
printf "TOTAL elapsed: %02d:%02d:%02d\n" \
    $((total_elapsed / 3600)) \
    $(((total_elapsed % 3600) / 60)) \
    $((total_elapsed % 60))
printf "Logs ở: %s/logs/linux/\n" "$(pwd)"
printf "=============================================\n"
