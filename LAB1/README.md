# Lab 1 — Symmetric Encryption với Crypto++

NT219 — Mật mã ứng dụng — UIT.
AES với 8 chế độ (ECB / CBC / CFB / OFB / CTR / XTS / GCM / CCM), key 128/192/256-bit,
encode binary/hex/base64. KAT runner dùng vector NIST chính thức, benchmark đến μs,
DLL export cho GUI Python.

## Cấu trúc

```
LAB1/
├── AES_benchmark.cpp     CLI benchmark + encrypt/decrypt thủ công
├── AES_KAT.cpp           KAT runner (NIST vectors)
├── aes_core.cpp / .h     Lõi DLL cho GUI (extern "C")
├── aes_gui.py            GUI Python (customtkinter)
├── KAT/                  NIST test vectors (CCM, GCM, AES KAT)
├── output/               CSV benchmark output theo hệ điều hành
├── run_negative_tests.py Negative test driver
└── .vscode/tasks.json    Lệnh build cho từng file
```

## Yêu cầu

- C++17, MinGW g++ (MSYS2)
- Crypto++ ≥ 8.6
- Python ≥ 3.10 + `customtkinter` (chỉ GUI)

## Build — Windows (MinGW)

Bằng tasks.json (VS Code) hoặc trực tiếp:

```powershell
$env:PATH = "C:\msys64\mingw64\bin;$env:PATH"
$INC = "D:\Study\NT219\CODE\Crypto++\include"
$LIB = "D:\Study\NT219\CODE\Crypto++\lib\cryptopp\gcc"

g++ -O3 -static AES_benchmark.cpp -I $INC -L $LIB -lcryptopp -lpthread -o AES_benchmark.exe
g++ -O3 -static AES_KAT.cpp       -I $INC -L $LIB -lcryptopp -lpthread -o AES_KAT.exe
g++ -O3 -shared -static -DAES_CORE_EXPORTS aes_core.cpp -I $INC -L $LIB -lcryptopp -o aes_core.dll
```

Đổi 2 biến `$INC`, `$LIB` nếu Crypto++ ở chỗ khác.

## Build — Linux (Ubuntu LTS)

```bash
sudo apt install build-essential libcrypto++-dev
g++ -O3 AES_benchmark.cpp -lcryptopp -lpthread -o AES_benchmark
g++ -O3 AES_KAT.cpp       -lcryptopp -lpthread -o AES_KAT
g++ -O3 -shared -fPIC -DAES_CORE_EXPORTS aes_core.cpp -lcryptopp -o aes_core.so
```

## Sử dụng

### Benchmark tự động (toàn bộ 8 mode × key size × payload)

```powershell
.\AES_benchmark.exe full_auto
```

```bash
./AES_benchmark full_auto
```

→ Windows ghi CSV vào `output/windows/benchmark_*.csv`, Linux ghi vào `output/linux/benchmark_*.csv`, với cột `Mode,File,Size,Operation,Run,Time(s),Throughput(MB/s)`.

### KAT (NIST vectors)

```powershell
.\AES_KAT.exe --kat
```

```bash
./AES_KAT --kat
```

### Sinh khoá + mã hoá thủ công

```powershell
# Sinh Key + IV ngẫu nhiên (ví dụ CBC, 16 byte)
.\AES_benchmark.exe genKeyIV CBC 16 Hex key.hex iv.hex

# Mã hoá (key/iv đang ở định dạng Hex, ciphertext output dạng Hex)
.\AES_benchmark.exe encrypt CBC Hex key.hex iv.hex Hex plain.txt cipher.hex --runs 30 --totalRounds 1

# Giải mã (đầu ra plaintext được ghi raw bytes ra file)
.\AES_benchmark.exe decrypt CBC Hex key.hex iv.hex Hex cipher.hex recovered.bin --runs 30 --totalRounds 1
```

```bash
# Sinh Key + IV ngẫu nhiên (ví dụ CBC, 16 byte)
./AES_benchmark genKeyIV CBC 16 Hex key.hex iv.hex

# Mã hoá (key/iv đang ở định dạng Hex, ciphertext output dạng Hex)
./AES_benchmark encrypt CBC Hex key.hex iv.hex Hex plain.txt cipher.hex --runs 30 --totalRounds 1

# Giải mã (đầu ra plaintext được ghi raw bytes ra file)
./AES_benchmark decrypt CBC Hex key.hex iv.hex Hex cipher.hex recovered.bin --runs 30 --totalRounds 1
```

### Negative tests

```powershell
python run_negative_tests.py
```

### GUI

```powershell
pip install customtkinter
python aes_gui.py
```

GUI tự sinh Key/IV bằng `os.urandom`, hỗ trợ encrypt/decrypt text hoặc file qua DLL `aes_core.dll`.

## Lưu ý đặc biệt

1. **Mode XTS** chỉ chấp nhận key 32 hoặc 64 byte (không có 16 byte). GUI tự switch khi chọn XTS.
2. **GCM / CCM (AEAD)** dùng IV 12 byte (96-bit) chuẩn NIST; có hỗ trợ AAD tùy chọn.
3. **Mode CCM** giới hạn file ~64 KB do cấu hình mặc định kích thước Nonce. Mode khác không giới hạn.
