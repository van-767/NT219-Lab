# Lab 2 — AES-128 CTR thủ công (FIPS-197)

NT219 — Mật mã ứng dụng — UIT.
Implement AES-128 (S-box, ShiftRows, MixColumns, KeyExpansion) **từ con số 0**
bằng C++ thuần, không thư viện ngoài. Mode CTR theo NIST SP 800-38A,
KAT theo FIPS-197 + SP 800-38A. DLL export cho GUI Python.

## Cấu trúc

```
LAB2/
├── ctr_mode.cpp          Toàn bộ logic AES + CTR + CLI + DLL export
├── fips_197.txt          NIST FIPS-197 test vectors
├── aes_gui.py            GUI Python (customtkinter)
├── ctr_mode.exe / .dll   Binary build sẵn
├── ctr_mode.so           Binary Linux
└── output/windows/       CSV benchmark
```

Single-file design — toàn bộ ~600 dòng C++, không build system rườm rà.

## Yêu cầu

- C++17, MinGW g++ (MSYS2) hoặc gcc Linux
- Python ≥ 3.10 + `customtkinter` (chỉ GUI)
- **Không** cần Crypto++ / OpenSSL

## Build — Windows (MinGW)

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

# CLI
g++ -O3 ctr_mode.cpp -o ctr_mode.exe

# DLL cho GUI
g++ -O3 -shared -static ctr_mode.cpp -o ctr_mode.dll
```

## Build — Linux

```bash
g++ -O3 ctr_mode.cpp -o ctr_mode
g++ -O3 -shared -fPIC ctr_mode.cpp -o ctr_mode.so
```

## Sử dụng

### KAT (FIPS-197 + SP 800-38A vectors)

```powershell
.\ctr_mode.exe --mode kat
```

### Benchmark (1 KiB → 8 MiB)

```powershell
.\ctr_mode.exe --mode benchmark
```
→ Output `output/windows/benchmark_ctr.csv`.

### Encrypt / Decrypt (hex)

```powershell
# Encrypt — key, IV, plaintext đều là hex
.\ctr_mode.exe --mode encrypt `
    --input 6bc1bee22e409f96e93d7e117393172a `
    --key   2b7e151628aed2a6abf7158809cf4f3c `
    --iv    f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

# Decrypt
.\ctr_mode.exe --mode decrypt --input <cipher_hex> --key <key_hex> --iv <iv_hex>
```

### GUI

```powershell
pip install customtkinter
python aes_gui.py
```

GUI hỗ trợ text mode hoặc file lớn (>100 MiB) qua DLL `ctr_mode.dll`.

## Lưu ý

1. **Không có padding** — CTR là stream cipher, ciphertext kích thước **bằng đúng** plaintext.
2. **Key + IV phải 16 byte** (32 ký tự hex) — implementation chuyên biệt AES-128.
3. **Single-file architecture** — build/port dễ, không cần CMake hay tasks.json.
