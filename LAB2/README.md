# Lab 2 — Manual AES-128 CTR Implementation

- Triển khai thủ công chuẩn xác thuật toán `AES-128` theo FIPS-197 hoàn toàn bằng C++ thuần, không sử dụng thư viện ngoài.
- Triển khai chế độ `CTR` (Counter Mode) biến AES thành một stream cipher thực thụ.
- Đo lường hiệu suất (Benchmark) vòng lặp tùy chỉnh chính xác tới microsecond (us), tự động xuất kết quả ra file `benchmark_ctr.csv`.
- Đi kèm tính năng kiểm tra tính đúng đắn (KAT) với vector chuẩn từ NIST FIPS-197 và SP 800-38A với output log siêu chi tiết.
- Đi kèm giao diện GUI trực quan (được viết bằng `customtkinter` của Python) giao tiếp với C++ qua DLL.

## Cấu trúc thư mục
- `ctr_mode.cpp`: Toàn bộ logic thuật toán AES, chế độ CTR, bộ đếm (Counter) và các công cụ CLI (Benchmark, KAT, Encrypt/Decrypt) được đóng gói gọn gàng, tối ưu trong một file duy nhất. File này cũng đóng vai trò làm thư viện DLL xuất ra cho Python gọi.
- `fips_197.txt`: File chứa các test vector chuẩn trích xuất từ tài liệu FIPS-197 để phục vụ cho tính năng chạy KAT.
- `aes_gui.py`: Giao diện người dùng bằng Python, sử dụng thư viện `customtkinter` để tương tác trực tiếp với lõi `ctr_mode`.

---

## 1. Hướng dẫn Biên dịch (Build Instructions)

Vui lòng mở Terminal/Command Prompt tại thư mục `LAB2` và chạy các lệnh dưới đây. Do mã nguồn đã được gom gọn vào một file duy nhất, việc biên dịch cực kỳ đơn giản.

### Trên Windows (MinGW)

**1. Build công cụ CLI (Console):**
```bash
g++ -O3 ctr_mode.cpp -o ctr_mode.exe
```

**2. Build thư viện DLL cho Python GUI:**
```bash
g++ -O3 -shared -static ctr_mode.cpp -o ctr_mode.dll
```

### Trên Linux

**1. Build công cụ CLI (Console):**
```bash
g++ -O3 ctr_mode.cpp -o ctr_mode
```

**2. Build thư viện .so cho Python GUI:**
```bash
g++ -O3 -shared -fPIC ctr_mode.cpp -o ctr_mode.so
```

---

## 2. Hướng dẫn Sử dụng Công cụ (CLI & GUI)

### 2.1. Chạy Benchmark 
Đo lường hiệu suất của bộ code thủ công với các kích thước dữ liệu khác nhau (1KiB - 8MiB):
```bash
.\ctr_mode.exe --mode benchmark
```
Kết quả hiển thị trực tiếp ra Terminal và đồng thời tự động lưu báo cáo vào thư mục `output/windows/benchmark_ctr.csv` để bạn phân tích.

### 2.2. Kiểm tra tính đúng đắn (KAT)
Chương trình sẽ tự động đọc file `fips_197.txt` và chạy bộ test nội bộ để đảm bảo thuật toán chuẩn xác 100%:
```bash
.\ctr_mode.exe --mode kat
```

### 2.3. Terminal Mode (Mã hóa / Giải mã chuỗi Hex)

**Mã hóa (Encrypt):**
Truyền vào Plaintext, Key và IV dưới dạng chuỗi Hex. Ví dụ:
```bash
.\ctr_mode.exe --mode encrypt --input 6bc1bee22e409f96e93d7e117393172a --key 2b7e151628aed2a6abf7158809cf4f3c --iv f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff
```

**Giải mã (Decrypt):**
Truyền vào Ciphertext, Key và IV dưới dạng chuỗi Hex.
```bash
.\ctr_mode.exe --mode decrypt --input <cipher_hex> --key <key_hex> --iv <iv_hex>
```

### 2.4. Giao diện Python GUI
Sau khi biên dịch thành công file thư viện động `ctr_mode.dll` (hoặc `.so`), khởi chạy GUI bằng lệnh:
```bash
python aes_gui.py
```
Trong giao diện này, việc **Sinh Key / IV (Hex)** hoàn toàn tự động và an toàn bằng hàm cấp hệ điều hành (os.urandom). Hỗ trợ mã hóa/giải mã dạng Text trực tiếp hoặc thao tác trên File cực lớn (hàng trăm MB) một cách vô cùng mượt mà.

---

## 3. Một Số Lưu Ý Quan Trọng

1. **Không Dùng Padding**:
   - Do CTR biến Cipher thành luồng Stream Cipher, nó không yêu cầu kích thước Plaintext phải là bội số của 16 như CBC. Bản mã tạo ra có kích thước đúng bằng bản rõ (từng byte một), vì thế chương trình **không cần** và **không sử dụng** bất kỳ thuật toán Padding nào.
   
2. **Thiết kế Single-File Architecture**:
   - Việc đưa toàn bộ logic (Core, Cipher, CLI, Benchmark, DLL Exporter) vào một file `ctr_mode.cpp` duy nhất giúp mã nguồn cực kỳ dễ đọc, dễ bảo trì và đặc biệt là dễ dàng mang đi biên dịch trên mọi môi trường (Windows/Linux) mà không lo lỗi cấu hình Build system rườm rà.

3. **Giới hạn đầu vào (CLI)**:
   - Khi dùng tính năng encrypt/decrypt trên CLI, các tham số `--input`, `--key`, `--iv` bắt buộc phải là chuỗi Hex hợp lệ. Key và IV phải có độ dài đúng 32 ký tự Hex (16 bytes = 128-bit) do mã nguồn được thiết kế chuyên biệt và tối ưu hóa chặt chẽ cho thuật toán AES-128.
