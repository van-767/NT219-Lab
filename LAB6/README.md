# Lab 6 — Post-Quantum Signatures & Certificates (ML-DSA + ML-KEM)

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
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-make git
```

cài `liboqs` vào ổ D tại `D:/Study/NT219/CODE/liboqs`
để không phụ thuộc vào thư mục hệ thống.

```bash
# Cach A: chay trong MSYS2 MINGW64 shell
cd /d/Study/NT219/CODE
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build && cd build
cmake -G "MinGW Makefiles" .. \
      -DCMAKE_INSTALL_PREFIX=D:/Study/NT219/CODE/liboqs \
      -DBUILD_SHARED_LIBS=OFF \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DOQS_DIST_BUILD=OFF \
      -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
mingw32-make -j2
mingw32-make install
```

Neu chay trong PowerShell thi dung cu phap PowerShell. Khong dung `cd /d/...`,
khong dung dau `\` de xuong dong, va PowerShell cu khong ho tro `&&`:

```powershell
# Cach B: chay trong PowerShell
Set-Location D:\Study\NT219\CODE
git clone --depth 1 https://github.com/open-quantum-safe/liboqs
Set-Location D:\Study\NT219\CODE\liboqs
New-Item -ItemType Directory -Force build
Set-Location build
cmake -G "MinGW Makefiles" .. -DCMAKE_INSTALL_PREFIX=D:/Study/NT219/CODE/liboqs -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=OFF -DOQS_MINIMAL_BUILD='KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87'
mingw32-make -j2
mingw32-make install
```

Sau khi cài xong, phải có các file chính:

```text
D:/Study/NT219/CODE/liboqs/include/oqs/oqs.h
D:/Study/NT219/CODE/liboqs/lib/liboqs.a
```

Nếu muốn dùng gói có sẵn của MSYS2 thay vì build source:

```bash
pacman -S mingw-w64-x86_64-liboqs
```

Khi đó lib và header nằm trong `C:\msys64\mingw64\{include,lib}` và CMake cũng tự dò được.

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
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++ -DLIBOQS_ROOT=D:/Study/NT219/CODE/liboqs
cmake --build build --parallel
Get-ChildItem .\bin\windows
```

Nếu trước đó đã cấu hình sai path hoặc thiếu `mingw32-make`, xoá thư mục `build/`
rồi chạy lại 2 lệnh build ở trên.

```bash
# Linux
cmake -B build -S .
cmake --build build -j
```

→ Output:
- `bin/{windows,linux}/MLDSA{,.exe}` — CLI ML-DSA
- `bin/{windows,linux}/MLKEM{,.exe}` — CLI ML-KEM
- `bin/{windows,linux}/libpq_core.{dll,so}` — shared lib cho GUI

## Windows copy-paste commands

Tất cả lệnh trong mục này chạy trực tiếp trong PowerShell từ bất kỳ thư mục nào.
Copy nguyên block là chạy được.

### Quick check sau khi build

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
Get-ChildItem .\bin\windows
.\bin\windows\MLDSA.exe kat --algo mldsa-44
.\bin\windows\MLKEM.exe kat --algo mlkem-512
```

### ML-DSA demo

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\bin\windows\MLDSA.exe keygen --algo mldsa-44 --priv priv.pem --pub pub.pem
Set-Content -Path msg.txt -Value "Hello Lab 6 - ML-DSA" -Encoding ASCII
.\bin\windows\MLDSA.exe sign --priv priv.pem --in msg.txt --out msg.sig
.\bin\windows\MLDSA.exe verify --pub pub.pem --in msg.txt --sig msg.sig
```

### ML-KEM demo

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\bin\windows\MLKEM.exe keygen --algo mlkem-512 --priv kem_priv.pem --pub kem_pub.pem
.\bin\windows\MLKEM.exe encaps --pub kem_pub.pem --ct ct.bin --ss ss_send.bin
.\bin\windows\MLKEM.exe decaps --priv kem_priv.pem --ct ct.bin --ss ss_recv.bin
(Get-FileHash ss_send.bin).Hash -eq (Get-FileHash ss_recv.bin).Hash
```

### PQ certificate demo

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\bin\windows\MLDSA.exe keygen --algo mldsa-44 --priv ca_priv.pem --pub ca_pub.pem
.\bin\windows\MLDSA.exe keygen --algo mldsa-44 --priv sub_priv.pem --pub sub_pub.pem
.\bin\windows\MLDSA.exe cert --make --ca-priv ca_priv.pem --ca-pub ca_pub.pem --subj-pub sub_pub.pem --subject "UIT-Student-22520123" --algo mldsa-44 --out cert.json
.\bin\windows\MLDSA.exe cert --verify --ca-pub ca_pub.pem --cert cert.json
```

### Quick benchmark

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\bin\windows\MLDSA.exe bench --op sign --algo mldsa-44 --n 3 --block 100 --size 1024 --log logs\windows\quick_mldsa_sign.csv
.\bin\windows\MLKEM.exe bench --op encaps --algo mlkem-512 --n 3 --block 100 --log logs\windows\quick_mlkem_encaps.csv
```

### Full benchmark

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\scripts\run_bench.ps1
```

## CLI — ML-DSA

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

# Sinh khoá
.\bin\windows\MLDSA.exe keygen --algo mldsa-44 --priv priv.pem --pub pub.pem

# Tạo message mẫu
Set-Content -Path msg.txt -Value "Hello Lab 6 - ML-DSA" -Encoding ASCII

# Ký (signature detached, raw bytes)
.\bin\windows\MLDSA.exe sign --priv priv.pem --in msg.txt --out msg.sig

# Verify
.\bin\windows\MLDSA.exe verify --pub pub.pem --in msg.txt --sig msg.sig

# Negative + correctness tests
.\bin\windows\MLDSA.exe kat --algo mldsa-44
```

## CLI — ML-KEM

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

# Sinh khoá
.\bin\windows\MLKEM.exe keygen --algo mlkem-512 --priv kem_priv.pem --pub kem_pub.pem

# Encapsulation (sender): ra ciphertext + shared secret
.\bin\windows\MLKEM.exe encaps --pub kem_pub.pem --ct ct.bin --ss ss_send.bin

# Decapsulation (receiver): lấy lại shared secret
.\bin\windows\MLKEM.exe decaps --priv kem_priv.pem --ct ct.bin --ss ss_recv.bin

# Verify shared secret match: file ss_send.bin và ss_recv.bin phải giống nhau
(Get-FileHash ss_send.bin).Hash -eq (Get-FileHash ss_recv.bin).Hash

# KAT
.\bin\windows\MLKEM.exe kat --algo mlkem-512
```

## PQ Certificate Mini-Project

JSON certificate được ML-DSA ký bởi CA:

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

# 1) Tạo CA + subject
.\bin\windows\MLDSA.exe keygen --algo mldsa-44 --priv ca_priv.pem  --pub ca_pub.pem
.\bin\windows\MLDSA.exe keygen --algo mldsa-44 --priv sub_priv.pem --pub sub_pub.pem

# 2) CA ký pubkey của subject → cert.json
.\bin\windows\MLDSA.exe cert --make --ca-priv ca_priv.pem --ca-pub ca_pub.pem --subj-pub sub_pub.pem --subject "UIT-Student-24521973" --algo mldsa-44 --out cert.json

# 3) Verify cert bằng CA pubkey
.\bin\windows\MLDSA.exe cert --verify --ca-pub ca_pub.pem --cert cert.json
# → CERT VERIFY OK
```

Cert format:
```json
{
  "subject": "UIT-Student-24521973",
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

- **Windows**:
```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\scripts\run_bench.ps1
```

- **Windows quick benchmark**:
```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
.\bin\windows\MLDSA.exe bench --op sign --algo mldsa-44 --n 3 --block 100 --size 1024 --log logs\windows\quick_mldsa_sign.csv
.\bin\windows\MLKEM.exe bench --op encaps --algo mlkem-512 --n 3 --block 100 --log logs\windows\quick_mlkem_encaps.csv
```

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
