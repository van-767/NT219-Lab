# Lab 4 Task 1 + 5 - Hashing Suite

Hash CLI ho tro **SHA-2** (224/256/384/512), **SHA-3** (224/256/384/512),
**SHAKE128/256** (XOF). File input duoc doc streaming theo chunk 64 KiB.
KAT dung NIST CAVP + FIPS-202. Benchmark dung warm-up 1s, `n=30`,
`block=1000`.

## Cau truc

```text
task1_hashing/
+-- src/
|   +-- hash_core.{h,cpp}     SHA-2/3/SHAKE qua Crypto++
|   +-- c_api.{h,cpp}         DLL exports cho GUI
|   +-- hashtool_cli.cpp      hashtool.exe (digest/kat/bench)
+-- gui/hash_gui.py           PySide6 GUI, goi libhash_core qua ctypes
+-- tests/kat_vectors.json    KAT theo NIST CAVP + FIPS-202
+-- tests/KAT_SOURCES.md      nguon test vector
+-- scripts/run_bench.{ps1,bat,sh}
+-- bin/{windows,linux}/      output sau khi build
+-- logs/{windows,linux}/     output benchmark CSV
+-- CMakeLists.txt
+-- README.md
```

## Build

### Windows - MinGW

Chay trong thu muc `LAB4\task1_hashing`:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build -j
```

Output mong doi:

```text
bin/windows/hashtool.exe
bin/windows/libhash_core.dll
```

### Linux

Chay trong thu muc `LAB4/task1_hashing`:

```bash
sudo apt install build-essential cmake libcrypto++-dev
cmake -B build -S .
cmake --build build -j
```

Output mong doi:

```text
bin/linux/hashtool
bin/linux/libhash_core.so
```

## Chay tren Windows

### Digest text

```powershell
.\bin\windows\hashtool.exe digest --algo sha256 --text "hello"
.\bin\windows\hashtool.exe digest --algo sha512 --text "hello"
.\bin\windows\hashtool.exe digest --algo sha3-256 --text "hello"
.\bin\windows\hashtool.exe digest --algo shake256 --text "abc" --outlen 64
```

### Digest file

```powershell
.\bin\windows\hashtool.exe digest --algo sha256 --in sample.bin
.\bin\windows\hashtool.exe digest --algo sha512 --in sample.bin
```

### Ghi digest ra file

```powershell
.\bin\windows\hashtool.exe digest --algo sha256 --in sample.bin --out sample.sha256.hex --encode hex
.\bin\windows\hashtool.exe digest --algo sha256 --in sample.bin --out sample.sha256.raw --encode raw
```

### Chay KAT

```powershell
.\bin\windows\hashtool.exe kat --kat tests\kat_vectors.json
```

Ket qua mong doi:

```text
Summary: 1662 passed, 0 failed, 1662 total.
```

### Benchmark mot case

```powershell
.\bin\windows\hashtool.exe bench --algo sha256 --size 1048576 --n 30 --block 1000 --log logs\windows\sha256_1MiB.csv
```

### Benchmark theo spec lab

Benchmark 4 thuat toan:

```text
sha256, sha512, sha3-256, sha3-512
```

Benchmark 4 kich thuoc:

```text
1 MiB, 8 MiB, 50 MiB, 100 MiB
```

Chay:

```powershell
.\scripts\run_bench.ps1
```

Hoac:

```powershell
.\scripts\run_bench.bat
```

CSV output nam tai:

```text
logs/windows/
```

## Chay tren Linux

### Digest

```bash
./bin/linux/hashtool digest --algo sha256 --text "hello"
./bin/linux/hashtool digest --algo sha512 --in sample.bin
./bin/linux/hashtool digest --algo shake256 --text "abc" --outlen 64
```

### KAT

```bash
./bin/linux/hashtool kat --kat tests/kat_vectors.json
```

Ket qua mong doi:

```text
Summary: 1662 passed, 0 failed, 1662 total.
```

### Benchmark

```bash
./scripts/run_bench.sh
```

CSV output nam tai:

```text
logs/linux/
```

## GUI

Windows:

```powershell
pip install PySide6
python gui\hash_gui.py
```

Linux:

```bash
pip install PySide6
python gui/hash_gui.py
```

GUI gom 3 tab:

```text
Digest      hash text/file
KAT         run tests/kat_vectors.json
Benchmark   benchmark mot case
```

GUI goi `libhash_core` qua `ctypes`, khong lap lai crypto logic.

## KAT sources

- SHA-224/256/384/512: NIST CAVP SHS byte-oriented test vectors
  (`shabytetestvectors.zip`, ShortMsg + LongMsg).
- SHA3-224/256/384/512: NIST CAVP SHA-3 byte-oriented test vectors
  (`sha-3bytetestvectors.zip`, ShortMsg + LongMsg).
- SHAKE128/256: expected output sinh theo dinh nghia XOF trong FIPS-202.
- Chi tiet nguon nam trong `tests/KAT_SOURCES.md`.

## Bench output

Moi file CSV co dang:

```text
algo,N,block,msg_size,round,us_per_op
SHA-256,30,1000,1048576,0,2031.5
...
# summary,mean,...,throughput_MiBps,500.4
```

Dong `summary` co san:

```text
mean, median, sd, ci95_lo, ci95_hi, throughput_MiBps
```

Dung cac gia tri nay de dien bang benchmark trong report.

## Dap ung yeu cau

| Yeu cau | Status |
|---|---|
| SHA-224/256/384/512 | OK |
| SHA3-224/256/384/512 | OK |
| SHAKE128/256 voi `--outlen` | OK |
| Streaming file input | OK, chunk 64 KiB |
| KAT JSON runner | OK, 1662 cases |
| Benchmark SHA-256/SHA-512/SHA3-256/SHA3-512 | OK |
| Benchmark 1 MiB / 8 MiB / 50 MiB / 100 MiB | OK |
| CSV log + stats | OK |
| GUI goi chung compiled library | OK |
