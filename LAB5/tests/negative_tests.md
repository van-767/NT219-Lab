# Lab 5 — Correctness & Negative Tests (CLI demo)

File này chứa toàn bộ lệnh CLI để **chạy tay** từng case theo spec Lab 5 §3.
Copy từng block, dán vào terminal là chạy được. Ở Windows dùng PowerShell,
Linux/MSYS2 dùng bash — phần lệnh `ECDSA / RSAPSS` giống nhau (Windows thay
bằng `.\bin\windows\ECDSA.exe` v.v).

Để chạy nhanh toàn bộ một lượt:

```powershell
.\bin\windows\ECDSA.exe  kat
.\bin\windows\RSAPSS.exe kat
```

`kat` tự sinh khoá + chữ ký trong `%TEMP%` rồi in `PASS/FAIL` từng case.
Phần dưới là **bản chạy tay tương đương**, kèm output mong đợi để báo cáo.

---

## 0. Setup — sinh khoá và message mẫu

```powershell
mkdir tests\work -Force | Out-Null
cd tests\work

# ECDSA P-256
..\..\bin\windows\ECDSA.exe keygen --algo ecdsa-p256 --priv ec_A_priv.pem --pub ec_A_pub.pem
..\..\bin\windows\ECDSA.exe keygen --algo ecdsa-p256 --priv ec_B_priv.pem --pub ec_B_pub.pem   # khoá "lạ"

# RSA-PSS 3072
..\..\bin\windows\RSAPSS.exe keygen --bits 3072 --priv rsa_A_priv.pem --pub rsa_A_pub.pem
..\..\bin\windows\RSAPSS.exe keygen --bits 3072 --priv rsa_B_priv.pem --pub rsa_B_pub.pem

# Hai message: msg1 hợp lệ, msg2 dùng cho case "modified message"
Set-Content -NoNewline -Encoding utf8 msg1.bin "Hello Lab5"
Set-Content -NoNewline -Encoding utf8 msg2.bin "Other msg"
```

(Bash: dùng `mkdir -p tests/work && cd tests/work` và `printf 'Hello Lab5' > msg1.bin`.)

---

## 1. Positive roundtrip (phải PASS — bằng chứng tool hoạt động)

```powershell
# ECDSA — sign DER (mặc định)
..\..\bin\windows\ECDSA.exe sign   --priv ec_A_priv.pem --in msg1.bin --out msg1.sig
..\..\bin\windows\ECDSA.exe verify --pub  ec_A_pub.pem  --in msg1.bin --sig msg1.sig
#  Expected: [OK] Signature valid

# ECDSA — sign raw (IEEE P1363 r||s)
..\..\bin\windows\ECDSA.exe sign   --priv ec_A_priv.pem --in msg1.bin --out msg1.raw --encode raw
..\..\bin\windows\ECDSA.exe verify --pub  ec_A_pub.pem  --in msg1.bin --sig msg1.raw --encode raw
#  Expected: [OK] Signature valid

# RSA-PSS — sign raw + SHA-256, salt = hashLen (mặc định)
..\..\bin\windows\RSAPSS.exe sign   --priv rsa_A_priv.pem --in msg1.bin --out msg1.rsapss
..\..\bin\windows\RSAPSS.exe verify --pub  rsa_A_pub.pem  --in msg1.bin --sig msg1.rsapss
#  Expected: [OK] Signature valid
```

---

## 2. Modified message → verify FAIL (spec §3, case 1)

```powershell
# ECDSA: dùng chữ ký của msg1, verify với msg2
..\..\bin\windows\ECDSA.exe verify --pub ec_A_pub.pem --in msg2.bin --sig msg1.sig
#  Expected: [FAIL] Signature INVALID    (exit code 1)

# RSA-PSS
..\..\bin\windows\RSAPSS.exe verify --pub rsa_A_pub.pem --in msg2.bin --sig msg1.rsapss
#  Expected: [FAIL] Signature INVALID
```

**Giải thích:** ECDSA và RSA-PSS đều ràng buộc chữ ký vào hash của message
nguyên bản. Đổi message ⇒ hash khác ⇒ phương trình verify không đồng nhất.

---

## 3. Modified signature → verify FAIL (spec §3, case 2)

```powershell
# Lật 1 byte ở giữa chữ ký
python -c "import sys; b=open('msg1.sig','rb').read(); open('msg1.sig.tamper','wb').write(b[:len(b)//2]+bytes([b[len(b)//2]^1])+b[len(b)//2+1:])"

..\..\bin\windows\ECDSA.exe verify --pub ec_A_pub.pem --in msg1.bin --sig msg1.sig.tamper
#  Expected: [FAIL] Signature INVALID

# Tương tự cho RSA-PSS
python -c "import sys; b=open('msg1.rsapss','rb').read(); open('msg1.rsapss.tamper','wb').write(b[:len(b)//2]+bytes([b[len(b)//2]^1])+b[len(b)//2+1:])"
..\..\bin\windows\RSAPSS.exe verify --pub rsa_A_pub.pem --in msg1.bin --sig msg1.rsapss.tamper
#  Expected: [FAIL] Signature INVALID
```

**Giải thích:** với ECDSA chỉ cần đổi 1 bit trong `(r,s)` đã khiến đẳng thức
`r ≡ x₁ mod n` sai. Với RSA-PSS, bất kỳ thay đổi bit nào trong số chữ ký
khiến EMSA-PSS decode ra `H'` không khớp `H(m)`.

---

## 4. Modified public key → verify FAIL (spec §3, case 3)

```powershell
# Dùng public key của B để verify chữ ký do A ký
..\..\bin\windows\ECDSA.exe verify --pub ec_B_pub.pem --in msg1.bin --sig msg1.sig
#  Expected: [FAIL] Signature INVALID

..\..\bin\windows\RSAPSS.exe verify --pub rsa_B_pub.pem --in msg1.bin --sig msg1.rsapss
#  Expected: [FAIL] Signature INVALID
```

**Giải thích:** chữ ký gắn liền với private key tương ứng. Public key khác
⇒ `g^x` (ECDSA) hoặc modulus N (RSA) khác ⇒ verify fail.

---

## 5. Wrong algorithm identifier → fail closed (spec §3, case 4)

```powershell
# Sai tên curve / encoding khi parse → CLI từ chối
..\..\bin\windows\ECDSA.exe keygen --algo ecdsa-p521 --priv x.pem --pub y.pem
#  Expected: ERROR: Unsupported curve: ecdsa-p521 (use ecdsa-p256 or ecdsa-p384)
#            exit code 1

..\..\bin\windows\ECDSA.exe sign --priv ec_A_priv.pem --in msg1.bin --out z.sig --encode rot13
#  Expected: ERROR: Unsupported sig encoding: rot13 (raw|der|base64)
```

**Giải thích:** CLI parse enum strict, không có fallback im lặng. Đúng tinh
thần *fail closed* của spec mục 5.

---

## 6. Wrong hash function → verify FAIL (spec §3, case 5)

```powershell
# ECDSA: ký với SHA-256, verify ép sang SHA-384
..\..\bin\windows\ECDSA.exe sign   --priv ec_A_priv.pem --in msg1.bin --out msg1.sig --hash sha256
..\..\bin\windows\ECDSA.exe verify --pub  ec_A_pub.pem  --in msg1.bin --sig msg1.sig --hash sha384
#  Expected: [FAIL] Signature INVALID

# RSA-PSS: ký SHA-256, verify SHA-384
..\..\bin\windows\RSAPSS.exe sign   --priv rsa_A_priv.pem --in msg1.bin --out msg1.rsapss --hash sha256
..\..\bin\windows\RSAPSS.exe verify --pub  rsa_A_pub.pem  --in msg1.bin --sig msg1.rsapss --hash sha384
#  Expected: [FAIL] Signature INVALID
```

**Giải thích:** verifier hash lại message bằng thuật toán khác ⇒ digest
khác ⇒ phương trình verify không thoả. Đây là một dạng *algorithm
substitution attack* — nếu tool âm thầm "đoán" hash từ chữ ký thì sẽ bị
chấp nhận; đúng spec phải bám theo `--hash` người dùng truyền vào.

---

## 7. Encoding mismatch → verify FAIL

```powershell
# ECDSA: ký DER, verify lừa nó parse như raw
..\..\bin\windows\ECDSA.exe sign   --priv ec_A_priv.pem --in msg1.bin --out msg1.der --encode der
..\..\bin\windows\ECDSA.exe verify --pub  ec_A_pub.pem  --in msg1.bin --sig msg1.der --encode raw
#  Expected: [FAIL] Signature INVALID

# RSA-PSS: ký raw, verify ép base64
..\..\bin\windows\RSAPSS.exe sign   --priv rsa_A_priv.pem --in msg1.bin --out msg1.raw   --encode raw
..\..\bin\windows\RSAPSS.exe verify --pub  rsa_A_pub.pem  --in msg1.bin --sig msg1.raw   --encode base64
#  Expected: [FAIL] Signature INVALID
```

**Giải thích:** sig encoding sai ⇒ parse ra mảng byte sai ⇒ verify fail.

---

## 8. Malformed key file → ERROR (fail closed)

```powershell
Set-Content -NoNewline broken.pem "this is not a real PEM"
..\..\bin\windows\ECDSA.exe sign --priv broken.pem --in msg1.bin --out x.sig
#  Expected: ERROR: parse private key: <openssl error>     (exit 1)

..\..\bin\windows\RSAPSS.exe sign --priv broken.pem --in msg1.bin --out x.sig
#  Expected: ERROR: parse private key: ...
```

---

## 9. RSA-PSS policy: từ chối keygen < 3072 bit

```powershell
..\..\bin\windows\RSAPSS.exe keygen --bits 2048 --priv weak.pem --pub weak_pub.pem
#  Expected: ERROR: Key size must be ≥ 3072 bits (spec Lab 5)
```

**Giải thích:** Lab 5 yêu cầu `RSA ≥ 3072 bit`. Tool block thẳng ở mục
`keygen` thay vì chỉ cảnh báo.

---

## 10. RSA-PSS: sai salt-length → verify FAIL

```powershell
# Ký với salt-len = 32 (mặc định = hashLen), verify ép salt-len = 16
..\..\bin\windows\RSAPSS.exe sign   --priv rsa_A_priv.pem --in msg1.bin --out msg1.rsapss
..\..\bin\windows\RSAPSS.exe verify --pub  rsa_A_pub.pem  --in msg1.bin --sig msg1.rsapss --salt-len 16
#  Expected: [FAIL] Signature INVALID
```

---

## 11. Batch verification (spec §3 "Include: Batch verification")

```powershell
mkdir batch_ok -Force | Out-Null
1..5 | ForEach-Object {
  Set-Content -NoNewline ("batch_ok\m_$_.bin") "payload-$_"
  ..\..\bin\windows\ECDSA.exe sign --priv ec_A_priv.pem `
       --in ("batch_ok\m_$_.bin") --out ("batch_ok\m_$_.sig") | Out-Null
}
..\..\bin\windows\ECDSA.exe batch --pub ec_A_pub.pem --dir batch_ok
#  Expected:
#    PASS  m_1.sig
#    PASS  m_2.sig
#    PASS  m_3.sig
#    PASS  m_4.sig
#    PASS  m_5.sig
#    Summary: 5/5 passed
```

Thêm 1 file hỏng để thấy báo lỗi từng cái:

```powershell
Copy-Item batch_ok\m_1.sig batch_ok\m_1.sig.bak
python -c "b=open('batch_ok/m_1.sig','rb').read(); open('batch_ok/m_1.sig','wb').write(b[:-1]+bytes([b[-1]^1]))"
..\..\bin\windows\ECDSA.exe batch --pub ec_A_pub.pem --dir batch_ok
#  Expected:
#    FAIL  m_1.sig
#    PASS  m_2.sig
#    ...
#    Summary: 4/5 passed       (exit code 1)
```

---

## 12. Tổng hợp — chạy `kat` xác nhận lại bằng máy

Sau khi đã demo thủ công ở trên, chạy:

```powershell
..\..\bin\windows\ECDSA.exe  kat
..\..\bin\windows\RSAPSS.exe kat
```

Mỗi case in `PASS` / `FAIL` rồi `Summary: N/N cases passed`. Exit code 0
nếu pass hết. Đây là "automated unit tests" theo spec — chạy được trong
CI mà không cần Catch2/GoogleTest, tránh phụ thuộc thư viện ngoài.

---

## Bảng đối chiếu spec ↔ test đã thực hiện

| Spec §3 case                              | Section ở trên |
|-------------------------------------------|----------------|
| Modified message → fails                  | 2              |
| Modified signature → fails                | 3              |
| Modified public key → fails               | 4              |
| Wrong algorithm identifier → fails        | 5              |
| Wrong hash function → fails               | 6              |
| Automated unit tests                      | 12 (`kat`)     |
| Batch verification (verify N signatures)  | 11             |
| Clear error codes & UX messages           | xuyên suốt — exit 0/1, prefix `[OK]`/`[FAIL]`/`ERROR:` |
