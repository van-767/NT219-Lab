# Lab 3 — RSA-OAEP & Hybrid Encryption

NT219 — Mật mã ứng dụng — UIT.
RSA-OAEP/SHA-256 + tự động chuyển sang hybrid AES-256-GCM khi plaintext
vượt giới hạn OAEP. Modulus ≥ 3072 bit, GCM IV 96-bit, tag 128-bit,
label bind cả OAEP encoding parameter và GCM AAD.

## Cấu trúc

```
LAB3/
├── src/        rsa_core (lõi), c_api (DLL), cli, tests
├── tests/      kat_vectors.json (10 correctness + negative tests)
├── gui/        rsa_gui.py — PySide6 GUI gọi DLL qua ctypes
├── scripts/    run_bench.ps1 / .sh / .bat — auto chạy 18 case bench
├── bin/        binary build ra
│   ├── windows/    rsatool.exe + librsa_core.dll
│   └── linux/      rsatool + librsa_core.so
├── logs/       output CSV của benchmark
│   ├── windows/    18 file CSV (Windows)
│   └── linux/      18 file CSV (Linux)
└── CMakeLists.txt
```

## Yêu cầu

| Thành phần | Phiên bản |
|---|---|
| C++ | 17 |
| CMake | ≥ 3.16 |
| Crypto++ | ≥ 8.6 |
| Python + PySide6 | (chỉ cho GUI) |

## Build Windows (MinGW từ MSYS2)

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build -j
```

CMake tự dò Crypto++ ở `D:/Study/NT219/CODE/Crypto++/lib/cryptopp/gcc/`.
Trỏ chỗ khác qua `-DCRYPTOPP_ROOT=...` nếu cần.

## Build Linux (Ubuntu LTS)

```bash
sudo apt install build-essential cmake libcrypto++-dev
cmake -B build -S .
cmake --build build -j
```

## Sử dụng CLI

```bash
# Sinh khoá
rsatool keygen --bits 3072 --priv priv.pem --pub pub.pem

# Mã hoá (tự switch hybrid khi msg > 318 byte)
rsatool encrypt --pub pub.pem --in msg.txt --out env.json --label "x"

# Giải mã (label phải khớp)
rsatool decrypt --priv priv.pem --in env.json --out plain.txt --label "x"

# Chạy 10 correctness + negative tests
rsatool kat --kat tests/kat_vectors.json
```

## Benchmark tự động

- **Windows**: double-click `scripts\run_bench.bat`
- **Linux**: `chmod +x scripts/run_bench.sh && ./scripts/run_bench.sh`

Script chạy đúng spec (warm-up 1s, n=30, block=1000) cho 18 case:

- RSA keygen / encrypt / decrypt × {3072, 4096} = 6 case
- AES-256-GCM encrypt / decrypt × {1, 4, 16, 256 KiB; 1, 8 MiB} = 12 case

Output CSV vào `logs/windows/` hoặc `logs/linux/`. Tổng thời gian ~5h.

## GUI

```bash
pip install PySide6
python gui/rsa_gui.py
```

4 tab: Keygen / Encrypt-Decrypt / KAT / Benchmark. GUI gọi DLL —
không lặp lại crypto logic (đáp ứng bonus +5).

## Envelope format

```json
{
  "mode": "RSA-OAEP-AES-GCM",
  "rsa_modulus": 3072,
  "hash": "SHA-256",
  "label": "x",
  "wrapped_key": "<base64>",
  "iv": "<base64>",
  "tag": "<base64>",
  "ciphertext": "<base64>"
}
```

Message ≤ `k − 2·hLen − 2` (318 byte với RSA-3072) thì `"mode":"RSA-OAEP"`
và chỉ có `ciphertext`.
