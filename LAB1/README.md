# Lab 1 — Symmetric Encryption with Crypto++

- Hỗ trợ đầy đủ 8 chế độ mã hóa: `ECB`, `CBC`, `CFB`, `OFB`, `CTR`, `XTS`, `GCM`, `CCM`.
- Hỗ trợ nhiều kích thước khóa (Key Size): `16 Bytes (128-bit)`, `24 Bytes (192-bit)`, `32 Bytes (256-bit)`.
- Hỗ trợ nhiều chuẩn định dạng đầu vào/đầu ra: `Binary`, `Hex`, `Base64`.
- Đo lường hiệu suất (Benchmark) chính xác tới microsecond (us).
- Tích hợp tính năng mã hóa xác thực AEAD cho `GCM` và `CCM` với tùy chỉnh tham số `AAD` và `Tag Size`.
- Đi kèm giao diện GUI trực quan (được viết bằng `customtkinter` của Python).

## Cấu trúc thư mục
- `AES_benchmark`: Thực hiện benchmark cho tất cả mode và chạy thủ công với các tham số tùy chỉnh.
- `AES_KAT`: Chạy known-answer tests (KAT) để kiểm tra tính đúng đắn của thuật toán.
- `aes_core`: Thư viện chính chứa logic mã hóa/giải mã, được biên dịch thành DLL/so để sử dụng trong GUI.
- `aes_gui.py`: Giao diện người dùng bằng Python, sử dụng thư viện `customtkinter` để tương tác với thư viện `aes_core`.
- `aes_core.h`: Header file định nghĩa API của thư viện `aes_core` để GUI có thể gọi.

## 1. Hướng dẫn Biên dịch (Build Instructions)

Vui lòng mở Terminal/Command Prompt tại thư mục `LAB1` và chạy các lệnh dưới đây (Lưu ý thay đổi đường dẫn `-I` và `-L` sao cho khớp với vị trí đặt thư viện `Crypto++` trên máy tính của bạn).

### Trên Windows (MinGW)

**1. Build công cụ Benchmark:**
```bash
g++ -O3 -static AES_benchmark.cpp -I "D:\Study\NT219\CODE\Crypto++\include" -L "D:\Study\NT219\CODE\Crypto++\lib\cryptopp\gcc" -lcryptopp -lpthread -o AES_benchmark.exe
```

**2. Build công cụ KAT:**
```bash
g++ -O3 -static AES_KAT.cpp -I "D:\Study\NT219\CODE\Crypto++\include" -L "D:\Study\NT219\CODE\Crypto++\lib\cryptopp\gcc" -lcryptopp -lpthread -o AES_KAT.exe
```

**3. Build thư viện DLL cho Python GUI:**
```bash
g++ -O3 -shared -static -DAES_CORE_EXPORTS aes_core.cpp -I "D:\Study\NT219\CODE\Crypto++\include" -L "D:\Study\NT219\CODE\Crypto++\lib\cryptopp\gcc" -lcryptopp -o aes_core.dll
```

### Trên Linux
```bash
g++ -O3 AES_benchmark.cpp -lcryptopp -lpthread -o AES_benchmark
g++ -O3 AES_KAT.cpp -lcryptopp -lpthread -o AES_KAT
g++ -O3 -shared -fPIC -DAES_CORE_EXPORTS aes_core.cpp -lcryptopp -o aes_core.so
```

---

## 2. Hướng dẫn Sử dụng Công cụ (CLI & GUI)

### 2.1. Chạy Tự Động Toàn Bộ Benchmark 
Cách nhanh nhất để lấy toàn bộ dữ liệu báo cáo:
```bash
.\AES_benchmark.exe full_auto
```
Output sẽ được ghi vào file `output/windows/benchmark_*.csv` với các thông tin `Mode,File,Size,Operation,Run,Time(s),Throughput(MB/s)` để phân tích

### 2.2. Kiểm tra tính đúng đắn (KAT)
```bash
.\AES_KAT.exe --kat
```

### 2.3. Terminal Mode

**Sinh Key và IV ngẫu nhiên (Ví dụ CBC, 16 bytes):**
```bash
AES_benchmark.exe genKeyIV CBC 16 Hex key.hex iv.hex
```

**Mã hóa file (Encrypt):**
```bash
AES_benchmark.exe encrypt CBC key.hex iv.hex Hex input.bin Hex cipher.hex --runs 30 --totalRounds 1
```

**Giải mã file (Decrypt):**
```bash
AES_benchmark.exe decrypt CBC key.hex iv.hex Hex cipher.hex Binary recovered.bin --runs 30 --totalRounds 1
```
### 2.4. Giao diện Python GUI
Sau khi biên dịch thành công file `aes_core.dll`, khởi chạy GUI bằng lệnh:
```bash
python aes_gui.py
```
Trong giao diện này, việc **Sinh Key / IV (Hex)** hoàn toàn tự động và an toàn bằng hàm cấp hệ điều hành (os.urandom). Hỗ trợ mã hóa/giải mã dạng Text trực tiếp hoặc chọn File vô cùng tiện lợi.

---

## 3. Một Số Lưu Ý Quan Trọng

1. **Mode XTS**: 
   - Yêu cầu kích thước Key bắt buộc phải là 32 Bytes hoặc 64 Bytes. Không hỗ trợ Key 16 Bytes.
   - Khi dùng tính năng `GENERATE KEY/IV` trên GUI, chương trình sẽ tự động cấp phát 32 Bytes khi bạn chọn XTS.

2. **Chế độ mã hóa có xác thực (GCM / CCM)**:
   - Các mode này hỗ trợ dữ liệu xác thực bổ sung `AAD` (Additional Authenticated Data).
   - Kích thước `IV` mặc định chuẩn cho GCM/CCM là 12 bytes (96 bit). Nếu bạn tự tạo IV, vui lòng sử dụng đúng 12 bytes. (Phần sinh IV tự động trên GUI đã được tối ưu hóa điều này).

3. **Giới hạn của Mode CCM**:
   - Thuật toán CCM bám sát tiêu chuẩn NIST SP 800-38C. Với thiết lập mặc định, phần định danh kích thước file sẽ bị hạn chế, khiến độ lớn file mã hóa đôi khi bị khóa ở ngưỡng 64KB.
