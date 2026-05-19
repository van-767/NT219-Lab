# Lab 5 — Classical Digital Signatures (ECDSA, RSA-PSS)

Bài này hiện thực ECDSA (P-256 mặc định, P-384 tùy chọn) và RSA-PSS-3072
(SHA-256, salt = 32 byte) theo yêu cầu Lab 5. Cùng một core C++ được
build ra hai CLI `ECDSA` / `RSAPSS` và một shared lib `libsig_core` cho
GUI Python gọi qua `ctypes` — đúng yêu cầu bonus của lab về
"GUI calls compiled library".

## Cấu trúc thư mục

```
LAB5/
├── src/
│   ├── ecdsa_core.{h,cpp}     phần lõi ECDSA (P-256 / P-384)
│   ├── rsapss_core.{h,cpp}    phần lõi RSA-PSS
│   ├── c_api.{h,cpp}          extern "C" cho file DLL/.so
│   ├── ecdsa_cli.cpp          chương trình dòng lệnh ECDSA
│   └── rsapss_cli.cpp         chương trình dòng lệnh RSA-PSS
├── gui/
│   └── sig_gui.py             GUI PySide6 (gọi DLL qua ctypes)
├── tests/                     (thư mục dành cho batch verify + tài liệu test)
├── CMakeLists.txt
└── README.md
```

## Yêu cầu môi trường

| Thành phần | Phiên bản |
|------------|-----------|
| C++        | C++17     |
| CMake      | ≥ 3.16    |
| OpenSSL    | ≥ 1.1.1 (khuyến nghị 3.x) |
| Python     | ≥ 3.10  (chỉ cho GUI) |
| PySide6    | mới nhất (chỉ cho GUI) |

## Build trên Windows (MinGW / g++ từ MSYS2)

```powershell
# Mở PowerShell tại thư mục LAB5, đảm bảo MinGW có trong PATH:
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"

cmake -B build -S . -G "MinGW Makefiles" `
      -DCMAKE_BUILD_TYPE=Release `
      -DCMAKE_C_COMPILER=gcc `
      -DCMAKE_CXX_COMPILER=g++
cmake --build build -j
```

Nếu OpenSSL không nằm trong PATH:

```powershell
cmake -B build -S . -G "MinGW Makefiles" `
      -DOPENSSL_ROOT_DIR="C:/Program Files/OpenSSL-Win64"
```

File ra (Release) nằm ở `bin/windows/`:

- `bin/windows/ECDSA.exe`        — CLI ECDSA
- `bin/windows/RSAPSS.exe`       — CLI RSA-PSS
- `bin/windows/libsig_core.dll`  — DLL cho GUI

### Build bằng MSVC (tuỳ chọn)

```powershell
cmake -B build-msvc -S . -A x64
cmake --build build-msvc --config Release
```

## Build trên Linux (Ubuntu LTS)

```bash
sudo apt install build-essential cmake libssl-dev
cmake -B build -S .
cmake --build build -j
```

File ra `bin/linux/`:
- `bin/linux/ECDSA`, `bin/linux/RSAPSS`, `bin/linux/libsig_core.so`

Vì binary Windows và Linux nằm ở hai thư mục con riêng (`bin/windows/`
vs `bin/linux/`), build lại bên nào **không ghi đè** lên bên kia.

## Cách dùng CLI

### ECDSA

```bash
# 1) Sinh cặp khoá P-256 (PEM, mặc định)
ECDSA keygen --algo ecdsa-p256 --priv ec_priv.pem --pub ec_pub.pem

#    P-384 + DER (bonus +5 theo spec):
ECDSA keygen --algo ecdsa-p384 --priv ec384_priv.der --pub ec384_pub.der --format der

# 2) Ký file → mặc định chữ ký DER (ASN.1) ghi ra .sig
ECDSA sign --priv ec_priv.pem --in msg.txt --out msg.sig

#    Ký dạng raw r||s (IEEE P1363) hoặc base64 cho dễ paste:
ECDSA sign --priv ec_priv.pem --in msg.txt --out msg.raw --encode raw
ECDSA sign --priv ec_priv.pem --in msg.txt --out msg.b64 --encode base64

# 3) Verify
ECDSA verify --pub ec_pub.pem --in msg.txt --sig msg.sig
ECDSA verify --pub ec_pub.pem --in msg.txt --sig msg.raw --encode raw

# 4) Batch verify: thư mục chứa từng cặp <name>.bin + <name>.sig
ECDSA batch --pub ec_pub.pem --dir tests/sigs/

# 5) Benchmark — theo đúng spec: warm-up 1 giây, N round, mỗi round
#    block ops, đo mean/median/sd/95%-CI per-op. Mặc định N=30, block=1000
#    (đúng yêu cầu trong PDF của Lab 5).
ECDSA bench --op sign   --algo ecdsa-p256 --n 30 --block 1000 --size 1024
ECDSA bench --op verify --algo ecdsa-p256 --n 30 --block 1000 --size 1024
ECDSA bench --op keygen --algo ecdsa-p256 --n 30 --block 100

#    Ghi log CSV để dựng bảng/biểu đồ trong report (import Excel/Pandas):
ECDSA bench --op sign --algo ecdsa-p256 --n 30 --block 1000 --size 1048576 \
            --log logs/ecdsa_sign_p256_1MB.csv
```

### RSA-PSS

```bash
# 1) Sinh cặp khoá 3072-bit PSS (PEM). Tool từ chối <3072 theo spec.
RSAPSS keygen --bits 3072 --priv rsa_priv.pem --pub rsa_pub.pem

# 2) Ký với SHA-256 + salt = hashLen (mặc định, đúng spec)
RSAPSS sign --priv rsa_priv.pem --in msg.txt --out msg.sig

#    Có thể chọn salt-len 0 (test only), encode base64:
RSAPSS sign --priv rsa_priv.pem --in msg.txt --out msg.b64 \
            --salt-len 0 --encode base64

# 3) Verify
RSAPSS verify --pub rsa_pub.pem --in msg.txt --sig msg.sig

# 4) Batch verify
RSAPSS batch --pub rsa_pub.pem --dir tests/sigs/

# 5) Benchmark — keygen RSA-3072 rất chậm, mặc định block=1000 sẽ tốn vài giờ.
#    Lúc test nhanh thì truyền --block 1:
RSAPSS bench --op keygen --bits 3072 --n 30 --block 1
RSAPSS bench --op sign   --bits 3072 --n 30 --block 1000 --size 1024
RSAPSS bench --op verify --bits 3072 --n 30 --block 1000 --size 1024 \
             --log logs/rsapss_verify_3072.csv
```

Định dạng CSV log:

```
op,algo|bits,N,block,msg_size,round,us_per_op
sign,ecdsa-p256,30,1000,1024,0,87.3
...
# summary,mean,87.21,median,86.50,sd,1.42,ci95_lo,86.71,ci95_hi,87.71
```

## Chạy GUI

```bash
pip install PySide6
python gui/sig_gui.py
```

GUI sẽ tự tìm `libsig_core.dll` / `libsig_core.so` ở: cùng thư mục với
file `.py`, `bin/windows/`, `bin/linux/`, hoặc `build/`. Toàn bộ crypto
chạy trong DLL — Python chỉ gọi qua C ABI khai báo ở `src/c_api.h`.

## Bảng negative test

| Tình huống                              | Kết quả mong muốn                |
|-----------------------------------------|----------------------------------|
| Sai message khi verify                  | `[FAIL] Signature INVALID`       |
| Sửa 1 byte trong file `.sig`            | `[FAIL] Signature INVALID`       |
| Sai public key                          | `[FAIL] Signature INVALID`       |
| `--hash sha384` khi ký bằng SHA-256     | `[FAIL] Signature INVALID`       |
| `--encode raw` nhưng sig là DER         | `[FAIL] Signature INVALID`       |
| Private key bị cắt / không đúng PEM     | `ERROR: parse private key: ...`  |
| `RSAPSS keygen --bits 2048`             | `ERROR: ... ≥ 3072 ...`          |

Cách tái hiện thủ công:

```bash
ECDSA sign   --priv ec_priv.pem --in msg.txt --out msg.sig
ECDSA verify --pub  ec_pub.pem  --in msg2.txt --sig msg.sig         # phải fail

# Lật 1 byte chữ ký
python -c "b=open('msg.sig','rb').read(); open('msg.sig','wb').write(bytes([b[0]^1])+b[1:])"
ECDSA verify --pub ec_pub.pem --in msg.txt --sig msg.sig             # phải fail
```

## Hạn chế đã biết

- ECDSA mặc định dùng OpenSSL nên là **nonce ngẫu nhiên** (an toàn nếu RNG
  tốt). Phần thảo luận trong report so sánh với RFC 6979 deterministic
  ECDSA (Crypto++ có hỗ trợ). Đây là điểm sẽ phân tích trong mục
  Security Discussion bonus.
- Salt length của RSA-PSS mặc định bằng hashLen (32 byte với SHA-256) —
  đúng spec; có thể override bằng `--salt-len N`.
- Benchmark dùng `std::chrono::steady_clock`. Việc pin CPU governor, tắt
  HyperThreading, isolate core,… như spec gợi ý là trách nhiệm của
  người chạy đo (xem hướng dẫn ở mục Reporting Template).

## Phân tích bảo mật (đối chiếu phần 5 của report)

- **ECDSA nonce reuse** ⇒ rò rỉ private key (lịch sử PlayStation 3). Phần
  report giải thích vì sao OpenSSL/Crypto++ đều dùng deterministic hoặc
  CSPRNG-driven nonce.
- **RSA-PSS ưu việt hơn PKCS#1 v1.5** vì có chứng minh bảo mật chặt chẽ
  trong ROM, không bị Bleichenbacher signature forgery.
- **Constant-time verify**: OpenSSL EVP_DigestVerifyFinal so sánh dùng
  hàm constant-time → không leak signature qua timing.
- **Fail-closed**: mọi đường parse đều validate, throw `runtime_error`;
  C API map exception thành mã lỗi khác 0 kèm `sig_last_error()` an toàn
  với thread (thread_local).
