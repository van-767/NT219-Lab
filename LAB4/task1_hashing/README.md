# Lab 4 Task 1 + 5 — Hashing Suite

Hash CLI hỗ trợ **SHA-2** (224/256/384/512), **SHA-3** (224/256/384/512),
**SHAKE128/256** (XOF). Streaming I/O cho file lớn. KAT theo NIST FIPS-180-4
+ FIPS-202. Benchmark đúng spec (warm-up 1s, n=30 × block=1000).

## Cấu trúc

```
task1_hashing/
├── src/
│   ├── hash_core.{h,cpp}     SHA-2/3/SHAKE qua Crypto++
│   ├── c_api.{h,cpp}         DLL exports cho GUI
│   └── hashtool_cli.cpp      → hashtool.exe (digest/kat/bench)
├── gui/hash_gui.py           PySide6 GUI (gọi libhash_core qua ctypes)
├── tests/kat_vectors.json    NIST KAT
├── scripts/run_bench.{ps1,bat,sh}
├── bin/{windows,linux}/      hashtool + libhash_core
├── logs/{windows,linux}/
├── CMakeLists.txt
└── README.md
```

## Build

### Windows (MinGW)
```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build -j
```

### Linux
```bash
sudo apt install build-essential cmake libcrypto++-dev
cmake -B build -S .
cmake --build build -j
```

## Sử dụng

```bash
# Digest
hashtool digest --algo sha256 --text "hello"
hashtool digest --algo sha512 --in bigfile.iso       # streaming
hashtool digest --algo shake256 --text "abc" --outlen 64

# Output ra file (raw bytes)
hashtool digest --algo sha256 --in file.bin --out file.sha256 --encode raw

# KAT (NIST vectors)
hashtool kat --kat tests/kat_vectors.json
# Mong đợi: Summary: 13 passed, 0 failed, 13 total.

# Benchmark 1 case
hashtool bench --algo sha256 --size 1048576 --log logs/windows/sha256_1MiB.csv

# Auto bench toàn bộ 4 algo × 4 size
.\scripts\run_bench.bat        # Windows
./scripts/run_bench.sh         # Linux
```

## GUI

```bash
pip install PySide6
python gui/hash_gui.py
```

3 tab: **Digest** (text/file, 10 algo + XOF), **KAT** (run 13 NIST vector),
**Benchmark** (per-algo per-size). GUI gọi `libhash_core.dll` qua ctypes —
không lặp crypto logic (đáp ứng bonus GUI).

## Bench output

Mỗi file CSV gồm:
```
algo,N,block,msg_size,round,us_per_op
SHA-256,30,1000,1048576,0,2031.5
...
# summary,mean,...,throughput_MiBps,500.4
```

→ Throughput tự tính sẵn ở dòng summary. Copy vào bảng report.

## Đáp ứng spec

| Yêu cầu (PDF §1+§2+§6) | Status |
|---|---|
| SHA-224/256/384/512 | ✓ |
| SHA3-224/256/384/512 | ✓ |
| SHAKE128/256 với `--outlen` | ✓ |
| Streaming I/O multi-GB | ✓ (chunk 64 KiB) |
| KAT JSON runner | ✓ 13 NIST vector |
| Benchmark 1 MiB / 100 MiB | ✓ + 1 KiB, 64 KiB |
| CSV log + stats | ✓ mean/median/sd/CI95 + MiB/s |
| Cross-platform | ✓ MinGW + Linux apt |
