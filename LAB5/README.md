# Lab 5 - Classical Digital Signatures (ECDSA, RSA-PSS)

Lab này hiện thực chữ ký số cổ điển bằng ECDSA và RSA-PSS. Chương trình có
CLI cho Windows/Linux, thư viện động cho GUI Python, test đúng/sai và script
benchmark tự động.

> Tất cả lệnh bên dưới chạy từ thư mục gốc `LAB5/`.

## Cấu Trúc Thư Mục

```text
LAB5/
├── bin/
│   ├── windows/
│   │   ├── ECDSA.exe
│   │   ├── RSAPSS.exe
│   │   └── libsig_core.dll
│   └── linux/
│       ├── ECDSA
│       ├── RSAPSS
│       └── libsig_core.so
├── gui/
│   └── sig_gui.py
├── logs/
│   ├── windows/
│   └── linux/
├── scripts/
│   ├── run_bench.ps1
│   ├── run_bench.bat
│   └── run_bench.sh
├── src/
│   ├── ecdsa_core.cpp / ecdsa_core.h
│   ├── rsapss_core.cpp / rsapss_core.h
│   ├── ecdsa_cli.cpp
│   ├── rsapss_cli.cpp
│   ├── c_api.cpp
│   └── c_api.h
├── tests/
│   └── negative_tests.md
├── CMakeLists.txt
└── README.md
```

## Yêu Cầu Môi Trường

| Thành phần | Yêu cầu |
|---|---|
| C++ | C++17 |
| CMake | >= 3.16 |
| OpenSSL | OpenSSL 3.x khuyến nghị |
| Windows compiler | MSYS2 MinGW64 g++ |
| Linux compiler | g++ / build-essential |
| GUI | Python 3 + PySide6 |

## Chạy Nhanh Trên Windows

Mở PowerShell tại thư mục `LAB5/`, sau đó chạy:

```powershell
.\bin\windows\ECDSA.exe help
.\bin\windows\RSAPSS.exe help
```

Nếu chương trình không chạy do thiếu DLL, thêm MSYS2 MinGW64 vào `PATH`:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
```

Sau đó chạy lại:

```powershell
.\bin\windows\ECDSA.exe help
.\bin\windows\RSAPSS.exe help
```

## Chạy Nhanh Trên Linux

Mở terminal tại thư mục `LAB5/`, sau đó chạy:

```bash
chmod +x ./bin/linux/ECDSA ./bin/linux/RSAPSS
./bin/linux/ECDSA help
./bin/linux/RSAPSS help
```

## Build Trên Windows

Mở PowerShell tại thư mục `LAB5/`:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

cmake -B build -S . -G "MinGW Makefiles" `
      -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_C_COMPILER=gcc `
      -DCMAKE_CXX_COMPILER=g++

cmake --build build -j
```

File build ra nằm ở:

```text
bin/windows/ECDSA.exe
bin/windows/RSAPSS.exe
bin/windows/libsig_core.dll
```

## Build Trên Linux

```bash
sudo apt install build-essential cmake libssl-dev
cmake -B build -S .
cmake --build build -j
```

File build ra nằm ở:

```text
bin/linux/ECDSA
bin/linux/RSAPSS
bin/linux/libsig_core.so
```

## Lệnh ECDSA Trên Windows

### Sinh Khóa

```powershell
.\bin\windows\ECDSA.exe keygen --algo ecdsa-p256 --priv ec_priv.pem --pub ec_pub.pem
```

P-384:

```powershell
.\bin\windows\ECDSA.exe keygen --algo ecdsa-p384 --priv ec384_priv.pem --pub ec384_pub.pem
```

### Ký File

Tạo file message mẫu:

```powershell
Set-Content -NoNewline -Encoding utf8 msg.txt "Hello Lab5 ECDSA"
```

Ký dạng DER mặc định:

```powershell
.\bin\windows\ECDSA.exe sign --priv ec_priv.pem --in msg.txt --out msg.sig
```

Ký dạng raw:

```powershell
.\bin\windows\ECDSA.exe sign --priv ec_priv.pem --in msg.txt --out msg.raw --encode raw
```

Ký dạng Base64:

```powershell
.\bin\windows\ECDSA.exe sign --priv ec_priv.pem --in msg.txt --out msg.b64 --encode base64
```

### Xác Minh Chữ Ký

```powershell
.\bin\windows\ECDSA.exe verify --pub ec_pub.pem --in msg.txt --sig msg.sig
```

Verify chữ ký raw:

```powershell
.\bin\windows\ECDSA.exe verify --pub ec_pub.pem --in msg.txt --sig msg.raw --encode raw
```

### Benchmark ECDSA

```powershell
.\bin\windows\ECDSA.exe bench --op keygen --algo ecdsa-p256 --n 30 --block 1000 --log logs\windows\ecdsa_p256_keygen.csv
.\bin\windows\ECDSA.exe bench --op sign   --algo ecdsa-p256 --n 30 --block 1000 --size 1024 --log logs\windows\ecdsa_p256_sign_1KiB.csv
.\bin\windows\ECDSA.exe bench --op verify --algo ecdsa-p256 --n 30 --block 1000 --size 1024 --log logs\windows\ecdsa_p256_verify_1KiB.csv
```

## Lệnh RSA-PSS Trên Windows

### Sinh Khóa

RSA-PSS 3072-bit:

```powershell
.\bin\windows\RSAPSS.exe keygen --bits 3072 --priv rsa_priv.pem --pub rsa_pub.pem
```

RSA-PSS 4096-bit:

```powershell
.\bin\windows\RSAPSS.exe keygen --bits 4096 --priv rsa4096_priv.pem --pub rsa4096_pub.pem
```

### Ký File

Tạo file message mẫu:

```powershell
Set-Content -NoNewline -Encoding utf8 msg.txt "Hello Lab5 RSA-PSS"
```

Ký mặc định SHA-256, salt length bằng hash length:

```powershell
.\bin\windows\RSAPSS.exe sign --priv rsa_priv.pem --in msg.txt --out msg.rsapss
```

Ký dạng Base64:

```powershell
.\bin\windows\RSAPSS.exe sign --priv rsa_priv.pem --in msg.txt --out msg.b64 --encode base64
```

### Xác Minh Chữ Ký

```powershell
.\bin\windows\RSAPSS.exe verify --pub rsa_pub.pem --in msg.txt --sig msg.rsapss
```

Verify Base64:

```powershell
.\bin\windows\RSAPSS.exe verify --pub rsa_pub.pem --in msg.txt --sig msg.b64 --encode base64
```

### Benchmark RSA-PSS

```powershell
.\bin\windows\RSAPSS.exe bench --op keygen --bits 3072 --n 30 --block 1000 --log logs\windows\rsapss_3072_keygen.csv
.\bin\windows\RSAPSS.exe bench --op sign   --bits 3072 --n 30 --block 1000 --size 1024 --log logs\windows\rsapss_3072_sign_1KiB.csv
.\bin\windows\RSAPSS.exe bench --op verify --bits 3072 --n 30 --block 1000 --size 1024 --log logs\windows\rsapss_3072_verify_1KiB.csv
```

Lưu ý: RSA-PSS keygen với `--block 1000` rất lâu, nhất là 4096-bit.

## Lệnh ECDSA Trên Linux

```bash
printf 'Hello Lab5 ECDSA' > msg.txt

./bin/linux/ECDSA keygen --algo ecdsa-p256 --priv ec_priv.pem --pub ec_pub.pem
./bin/linux/ECDSA sign --priv ec_priv.pem --in msg.txt --out msg.sig
./bin/linux/ECDSA verify --pub ec_pub.pem --in msg.txt --sig msg.sig
```

Benchmark:

```bash
./bin/linux/ECDSA bench --op keygen --algo ecdsa-p256 --n 30 --block 1000 --log logs/linux/ecdsa_p256_keygen.csv
./bin/linux/ECDSA bench --op sign   --algo ecdsa-p256 --n 30 --block 1000 --size 1024 --log logs/linux/ecdsa_p256_sign_1KiB.csv
./bin/linux/ECDSA bench --op verify --algo ecdsa-p256 --n 30 --block 1000 --size 1024 --log logs/linux/ecdsa_p256_verify_1KiB.csv
```

## Lệnh RSA-PSS Trên Linux

```bash
printf 'Hello Lab5 RSA-PSS' > msg.txt

./bin/linux/RSAPSS keygen --bits 3072 --priv rsa_priv.pem --pub rsa_pub.pem
./bin/linux/RSAPSS sign --priv rsa_priv.pem --in msg.txt --out msg.rsapss
./bin/linux/RSAPSS verify --pub rsa_pub.pem --in msg.txt --sig msg.rsapss
```

Benchmark:

```bash
./bin/linux/RSAPSS bench --op keygen --bits 3072 --n 30 --block 1000 --log logs/linux/rsapss_3072_keygen.csv
./bin/linux/RSAPSS bench --op sign   --bits 3072 --n 30 --block 1000 --size 1024 --log logs/linux/rsapss_3072_sign_1KiB.csv
./bin/linux/RSAPSS bench --op verify --bits 3072 --n 30 --block 1000 --size 1024 --log logs/linux/rsapss_3072_verify_1KiB.csv
```

## Chạy Test Tự Động

### Windows

```powershell
.\bin\windows\ECDSA.exe kat --algo ecdsa-p256
.\bin\windows\ECDSA.exe kat --algo ecdsa-p384
.\bin\windows\RSAPSS.exe kat --bits 3072
.\bin\windows\RSAPSS.exe kat --bits 4096
```

### Linux

```bash
./bin/linux/ECDSA kat --algo ecdsa-p256
./bin/linux/ECDSA kat --algo ecdsa-p384
./bin/linux/RSAPSS kat --bits 3072
./bin/linux/RSAPSS kat --bits 4096
```

Kết quả đúng là tất cả case đều `PASS`.

## Chạy Benchmark Hàng Loạt

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File scripts\run_bench.ps1
```

Hoặc:

```powershell
.\scripts\run_bench.bat
```

Log CSV được ghi vào:

```text
logs/windows/
```

### Linux

```bash
chmod +x scripts/run_bench.sh
./scripts/run_bench.sh
```

Log CSV được ghi vào:

```text
logs/linux/
```

## Định Dạng Log CSV

ECDSA:

```text
op,algo,N,block,msg_size,round,us_per_op
sign,ecdsa-p256,30,1000,1024,0,114.710
...
# summary,mean,114.710,median,...,sd,...,ci95_lo,...,ci95_hi,...
```

RSA-PSS:

```text
op,bits,N,block,msg_size,hash,round,us_per_op
sign,3072,30,1000,1024,sha256,0,2860.450
...
# summary,mean,2860.450,median,...,sd,...,ci95_lo,...,ci95_hi,...
```

## Chạy GUI

Cài PySide6:

```powershell
pip install PySide6
```

Chạy GUI:

```powershell
python gui\sig_gui.py
```

GUI sẽ tự tìm thư viện:

```text
bin/windows/libsig_core.dll
bin/linux/libsig_core.so
```

## Các Trường Hợp Test Sai

| Tình huống | Kết quả mong muốn |
|---|---|
| Thay đổi message sau khi ký | `[FAIL] Signature INVALID` |
| Sửa 1 byte trong chữ ký | `[FAIL] Signature INVALID` |
| Dùng sai public key | `[FAIL] Signature INVALID` |
| Dùng sai hash khi verify | `[FAIL] Signature INVALID` |
| Dùng sai encoding chữ ký | `[FAIL] Signature INVALID` |
| Private key sai định dạng | `ERROR: parse private key: ...` |
| RSA keygen nhỏ hơn 3072 bit | `ERROR: Key size must be >= 3072 bits` |

Ví dụ Windows:

```powershell
Set-Content -NoNewline -Encoding utf8 msg1.txt "Hello Lab5"
Set-Content -NoNewline -Encoding utf8 msg2.txt "Tampered message"

.\bin\windows\ECDSA.exe keygen --algo ecdsa-p256 --priv ec_priv.pem --pub ec_pub.pem
.\bin\windows\ECDSA.exe sign --priv ec_priv.pem --in msg1.txt --out msg.sig
.\bin\windows\ECDSA.exe verify --pub ec_pub.pem --in msg2.txt --sig msg.sig
```

Kết quả mong muốn:

```text
[FAIL] Signature INVALID
```