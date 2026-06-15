# Lab 6 - Post-Quantum Cryptography

Lab này cài đặt và benchmark 2 nhóm thuật toán hậu lượng tử:

- `ML-DSA`: sinh khóa, ký, xác minh chữ ký, tạo chứng chỉ JSON.
- `ML-KEM`: sinh khóa, encapsulation, decapsulation, so sánh shared secret.

Thư viện nền dùng trong bài là `liboqs`.

## Cấu trúc

```text
LAB6/
├── src/                  source C++
├── scripts/              script benchmark
├── gui/                  GUI Python nếu cần
├── bin/windows/          file chạy Windows
├── bin/linux/            file chạy Linux
├── logs/windows/         log benchmark Windows
├── logs/linux/           log benchmark Linux
├── liboqs-src/           source liboqs trên Linux
├── liboqs-build/         build folder liboqs trên Linux
├── liboqs/               liboqs đã install local trên Linux
├── CMakeLists.txt
└── README.md
```

## Yêu cầu

- C++17
- CMake >= 3.16
- gcc/g++ hoặc MinGW g++
- `liboqs` >= 0.10
- OpenSSL development library

## Linux - cài liboqs local

Không dùng `sudo apt install liboqs-dev` vì trên nhiều bản Ubuntu package này không có sẵn.
Ta build `liboqs` vào ngay thư mục `LAB6/liboqs`, không cài vào hệ thống.

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB6

sudo apt update
sudo apt install build-essential cmake ninja-build git libssl-dev
```

Nếu chưa có `liboqs-src`, clone source:

```bash
git clone --depth 1 --branch 0.10.1 https://github.com/open-quantum-safe/liboqs liboqs-src
```

Build và install local:

```bash
rm -rf liboqs-build liboqs

cmake -S liboqs-src -B liboqs-build -GNinja \
  -DCMAKE_INSTALL_PREFIX=$PWD/liboqs \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"

cmake --build liboqs-build -j
cmake --install liboqs-build
```

Kiểm tra phải có 2 file chính:

```bash
ls liboqs/include/oqs/oqs.h
ls liboqs/lib/liboqs.a
```

## Linux - build Lab 6

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB6

rm -rf build
cmake -B build -S . -DLIBOQS_ROOT=$PWD/liboqs
cmake --build build -j
```

Output sau khi build:

```text
bin/linux/MLDSA
bin/linux/MLKEM
bin/linux/libpq_core.so
```

Quick check:

```bash
./bin/linux/MLDSA kat --algo mldsa-65
./bin/linux/MLKEM kat --algo mlkem-512
```

Kết quả đúng sẽ có dạng:

```text
Summary: 8/8 cases passed
Summary: 6/6 cases passed
```

## Windows - cài liboqs bằng MSYS2

Chạy trong MSYS2 MinGW64 shell:

```bash
pacman -Syu
pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-gcc mingw-w64-x86_64-make git
```

Build `liboqs` vào `D:/Study/NT219/CODE/liboqs`:

```bash
cd /d/Study/NT219/CODE
git clone --depth 1 --branch 0.10.1 https://github.com/open-quantum-safe/liboqs
cd liboqs
mkdir build
cd build

cmake -G "MinGW Makefiles" .. \
  -DCMAKE_INSTALL_PREFIX=D:/Study/NT219/CODE/liboqs \
  -DBUILD_SHARED_LIBS=OFF \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_DIST_BUILD=OFF \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"

mingw32-make -j2
mingw32-make install
```

Kiểm tra:

```text
D:/Study/NT219/CODE/liboqs/include/oqs/oqs.h
D:/Study/NT219/CODE/liboqs/lib/liboqs.a
```

## Windows - build Lab 6

Chạy trong PowerShell:

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

Remove-Item -Recurse -Force build -ErrorAction SilentlyContinue
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++ -DLIBOQS_ROOT=D:/Study/NT219/CODE/liboqs
cmake --build build --parallel
```

Output sau khi build:

```text
bin/windows/MLDSA.exe
bin/windows/MLKEM.exe
bin/windows/libpq_core.dll
```

Quick check:

```powershell
.\bin\windows\MLDSA.exe kat --algo mldsa-65
.\bin\windows\MLKEM.exe kat --algo mlkem-512
```

## ML-DSA demo

Linux:

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB6

./bin/linux/MLDSA keygen --algo mldsa-65 --priv mldsa_priv.pem --pub mldsa_pub.pem
printf "Hello Lab 6 - ML-DSA\n" > msg.txt
./bin/linux/MLDSA sign --priv mldsa_priv.pem --in msg.txt --out msg.sig
./bin/linux/MLDSA verify --pub mldsa_pub.pem --in msg.txt --sig msg.sig
```

Windows:

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

.\bin\windows\MLDSA.exe keygen --algo mldsa-65 --priv mldsa_priv.pem --pub mldsa_pub.pem
Set-Content -Path msg.txt -Value "Hello Lab 6 - ML-DSA" -Encoding ASCII
.\bin\windows\MLDSA.exe sign --priv mldsa_priv.pem --in msg.txt --out msg.sig
.\bin\windows\MLDSA.exe verify --pub mldsa_pub.pem --in msg.txt --sig msg.sig
```

## ML-KEM demo

Linux:

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB6

./bin/linux/MLKEM keygen --algo mlkem-512 --priv kem_priv.pem --pub kem_pub.pem
./bin/linux/MLKEM encaps --pub kem_pub.pem --ct ct.bin --ss ss_send.bin
./bin/linux/MLKEM decaps --priv kem_priv.pem --ct ct.bin --ss ss_recv.bin
sha256sum ss_send.bin ss_recv.bin
cmp ss_send.bin ss_recv.bin && echo "Shared secret match"
```

Windows:

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

.\bin\windows\MLKEM.exe keygen --algo mlkem-512 --priv kem_priv.pem --pub kem_pub.pem
.\bin\windows\MLKEM.exe encaps --pub kem_pub.pem --ct ct.bin --ss ss_send.bin
.\bin\windows\MLKEM.exe decaps --priv kem_priv.pem --ct ct.bin --ss ss_recv.bin
(Get-FileHash ss_send.bin).Hash -eq (Get-FileHash ss_recv.bin).Hash
```

## PQ certificate demo

Linux:

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB6

./bin/linux/MLDSA keygen --algo mldsa-65 --priv ca_priv.pem --pub ca_pub.pem
./bin/linux/MLDSA keygen --algo mldsa-65 --priv sub_priv.pem --pub sub_pub.pem
./bin/linux/MLDSA cert --make --ca-priv ca_priv.pem --ca-pub ca_pub.pem --subj-pub sub_pub.pem --subject "UIT-Student-24521973" --algo mldsa-65 --out cert.json
./bin/linux/MLDSA cert --verify --ca-pub ca_pub.pem --cert cert.json
```

Windows:

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

.\bin\windows\MLDSA.exe keygen --algo mldsa-65 --priv ca_priv.pem --pub ca_pub.pem
.\bin\windows\MLDSA.exe keygen --algo mldsa-65 --priv sub_priv.pem --pub sub_pub.pem
.\bin\windows\MLDSA.exe cert --make --ca-priv ca_priv.pem --ca-pub ca_pub.pem --subj-pub sub_pub.pem --subject "UIT-Student-24521973" --algo mldsa-65 --out cert.json
.\bin\windows\MLDSA.exe cert --verify --ca-pub ca_pub.pem --cert cert.json
```

## Benchmark

Linux quick benchmark:

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB6

mkdir -p logs/linux
./bin/linux/MLDSA bench --op sign --algo mldsa-65 --n 3 --block 100 --size 1024 --log logs/linux/quick_mldsa65_sign.csv
./bin/linux/MLDSA bench --op verify --algo mldsa-65 --n 3 --block 100 --size 1024 --log logs/linux/quick_mldsa65_verify.csv
./bin/linux/MLKEM bench --op encaps --algo mlkem-512 --n 3 --block 100 --log logs/linux/quick_mlkem512_encaps.csv
./bin/linux/MLKEM bench --op decaps --algo mlkem-512 --n 3 --block 100 --log logs/linux/quick_mlkem512_decaps.csv
```

Windows quick benchmark:

```powershell
Set-Location D:\Study\NT219\CODE\BTVN\LAB6
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

.\bin\windows\MLDSA.exe bench --op sign --algo mldsa-65 --n 3 --block 100 --size 1024 --log logs\windows\quick_mldsa65_sign.csv
.\bin\windows\MLDSA.exe bench --op verify --algo mldsa-65 --n 3 --block 100 --size 1024 --log logs\windows\quick_mldsa65_verify.csv
.\bin\windows\MLKEM.exe bench --op encaps --algo mlkem-512 --n 3 --block 100 --log logs\windows\quick_mlkem512_encaps.csv
.\bin\windows\MLKEM.exe bench --op decaps --algo mlkem-512 --n 3 --block 100 --log logs\windows\quick_mlkem512_decaps.csv
```

Full benchmark:

```bash
# Linux
./scripts/run_bench.sh
```

```powershell
# Windows
.\scripts\run_bench.ps1
```

## Lưu ý lỗi thường gặp

Nếu `apt` báo không có `liboqs-dev`, bỏ qua package đó và build local theo mục Linux.

Nếu CMake báo không tìm thấy `Ninja`, chạy:

```bash
sudo apt install ninja-build
```

Nếu build báo lỗi `undefined reference to RAND_bytes`, `EVP_MD_fetch` hoặc `CRYPTO_THREAD_run_once`, nghĩa là thiếu link OpenSSL `libcrypto`. File `CMakeLists.txt` hiện đã link `OpenSSL::Crypto`, chỉ cần xóa `build` rồi cấu hình lại:

```bash
rm -rf build
cmake -B build -S . -DLIBOQS_ROOT=$PWD/liboqs
cmake --build build -j
```
