# Lab 6 — Post-Quantum Signatures & Certificates (ML-DSA + ML-KEM)

NT219 — Mật mã ứng dụng — UIT.
Implement ML-DSA (FIPS 204) sign/verify + ML-KEM (FIPS 203) encaps/decaps
qua **liboqs** (Open Quantum Safe). Hỗ trợ ML-DSA-44/65/87 và ML-KEM-512/768/1024.
Kèm PQ Certificate mini-project (ML-DSA-signed JSON).

## Cấu trúc

```
LAB6/
├── src/
│   ├── pq_core.{h,cpp}       Lõi ML-DSA + ML-KEM dùng liboqs
│   ├── c_api.{h,cpp}         extern "C" cho DLL gọi từ Python/C#
│   ├── mldsa_cli.cpp         → MLDSA.exe (keygen/sign/verify/batch/bench/kat/cert)
│   └── mlkem_cli.cpp         → MLKEM.exe (keygen/encaps/decaps/bench/kat)
├── gui/pq_gui.py             PySide6 GUI (gọi libpq_core qua ctypes)
├── scripts/                  auto bench: run_bench.{ps1,bat,sh}
├── bin/{windows,linux}/      binary
├── logs/{windows,linux}/     CSV bench output
├── CMakeLists.txt
└── README.md
```

## Yêu cầu

- C++17, CMake ≥ 3.16
- **liboqs ≥ 0.10** (NIST PQC reference)
- gcc/clang/MSVC

## Cài liboqs — Windows (MSYS2 MinGW64)

```bash
# Trong MSYS2 MINGW64 shell
pacman -Syu
pacman -S mingw-w64-x86_64-liboqs mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc
```

→ Lib và header tự đặt vào `C:\msys64\mingw64\{include,lib}\`. CMake tự dò ra.

Nếu pacman không có liboqs sẵn (gói cũ), build từ source:
```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -G "MinGW Makefiles" .. \
      -DCMAKE_INSTALL_PREFIX=C:/liboqs \
      -DBUILD_SHARED_LIBS=OFF
mingw32-make -j
mingw32-make install
```
Rồi build Lab 6 với `-DLIBOQS_ROOT=C:/liboqs`.

## Cài liboqs — Linux (Ubuntu LTS)

```bash
# Cách 1: apt (Ubuntu 24.04+)
sudo apt install liboqs-dev

# Cách 2: build từ source (mọi distro)
sudo apt install build-essential cmake ninja-build libssl-dev
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja && sudo ninja install
sudo ldconfig
```

## Build Lab 6

```powershell
# Windows
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build -j
```

```bash
# Linux
cmake -B build -S .
cmake --build build -j
```

→ Output:
- `bin/{windows,linux}/MLDSA{,.exe}` — CLI ML-DSA
- `bin/{windows,linux}/MLKEM{,.exe}` — CLI ML-KEM
- `bin/{windows,linux}/libpq_core.{dll,so}` — shared lib cho GUI

## CLI — ML-DSA

```bash
# Sinh khoá
MLDSA keygen --algo mldsa-44 --priv priv.pem --pub pub.pem

# Ký (signature detached, raw bytes)
MLDSA sign --priv priv.pem --in msg.bin --out msg.sig

# Verify
MLDSA verify --pub pub.pem --in msg.bin --sig msg.sig

# Negative + correctness tests
MLDSA kat --algo mldsa-44
```

## CLI — ML-KEM

```bash
# Sinh khoá
MLKEM keygen --algo mlkem-512 --priv priv.pem --pub pub.pem

# Encapsulation (sender): ra ciphertext + shared secret
MLKEM encaps --pub pub.pem --ct ct.bin --ss ss_send.bin

# Decapsulation (receiver): lấy lại shared secret
MLKEM decaps --priv priv.pem --ct ct.bin --ss ss_recv.bin

# Verify shared secret match: file ss_send.bin và ss_recv.bin phải giống nhau
diff ss_send.bin ss_recv.bin   # không có output = OK

# KAT
MLKEM kat --algo mlkem-512
```

## PQ Certificate Mini-Project

JSON certificate được ML-DSA ký bởi CA:

```bash
# 1) Tạo CA + subject
MLDSA keygen --algo mldsa-44 --priv ca_priv.pem  --pub ca_pub.pem
MLDSA keygen --algo mldsa-44 --priv sub_priv.pem --pub sub_pub.pem

# 2) CA ký pubkey của subject → cert.json
MLDSA cert --make \
    --ca-priv ca_priv.pem --ca-pub ca_pub.pem \
    --subj-pub sub_pub.pem --subject "UIT-Student-22520123" \
    --algo mldsa-44 --out cert.json

# 3) Verify cert bằng CA pubkey
MLDSA cert --verify --ca-pub ca_pub.pem --cert cert.json
# → CERT VERIFY OK
```

Cert format:
```json
{
  "subject": "UIT-Student-22520123",
  "algorithm": "ML-DSA-44",
  "public_key": "<base64 raw>",
  "issuer": "PQ-CA",
  "signature": "<base64 ML-DSA sig over (subject || pubkey)>"
}
```

## GUI (PySide6)

```bash
pip install PySide6
python gui/pq_gui.py
```

4 tab: **ML-DSA** (keygen/sign/verify) — **ML-KEM** (keygen/encaps/decaps) —
**Certificate** (make/verify cert.json) — **KAT** (chạy 8/8 ML-DSA + 6/6 ML-KEM).
GUI gọi `libpq_core.dll` qua ctypes, không lặp crypto logic (đáp ứng bonus +5).

## Benchmark tự động

- **Windows**: double-click `scripts\run_bench.bat`
- **Linux**: `chmod +x scripts/run_bench.sh && ./scripts/run_bench.sh`

Chạy 22 case: ML-DSA-44/65 (keygen + sign×4size + verify×4size) +
ML-KEM-512/768/1024 (keygen + encaps + decaps). Output `logs/{windows,linux}/*.csv`.

## Lưu ý

1. **ML-DSA deterministic** mặc định (FIPS 204) — không bị nonce reuse như ECDSA cổ điển.
2. **ML-KEM IND-CCA** qua Fujisaki-Okamoto transform — modify ciphertext không leak shared secret thật, decaps trả ra "implicit rejection" SS khác.
3. **Key + signature size lớn**:
   - ML-DSA-44 pubkey 1312B, sig ~2420B (so với ECDSA-P256 32B + 64B).
   - ML-KEM-512 pubkey 800B, ct 768B (so với RSA-3072 384B).
   - Đây là trade-off cho quantum resistance.
