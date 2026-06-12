# Lab 4 — Length-Extension Attack on Naive MAC

NT219 — Mat ma ung dung — UIT.
Task nay minh hoa loi thiet ke MAC kieu `SHA256(key || message)`.
Ke tan cong khong biet `key`, nhung biet message goc, MAC goc va do dai key,
tu do forge duoc message moi va MAC moi hop le bang HashPump.

## Cau truc

```
LAB4/attacks/length_extension/
├── README.md     Huong dan chay, giai thich va noi dung dua vao report
└── result.txt    Output HashPump: forged MAC + forged extended message
```

Tool su dung:

```
LAB4/tools/HashPump/
├── HashPump      Binary da build
├── main.cpp      CLI HashPump, da sua digest length cho SHA-256
└── *.cpp/*.h     MD4/MD5/SHA1/SHA256/SHA512 extender
```
Target insecure construction:

```text
MAC = H(k || m)
```

Voi SHA-256:

```text
MAC = SHA256(secret_key || message)
```

## Du lieu demo

Scenario nay lay tu file guide cua Lab 4:

```text
Original message:
user=guest&role=user

Original MAC:
c8e31557f57905134ab15990e56d8ab6f60ca1c8d6a4517908d57867f3327519

Secret key length:
14 bytes

Data to append:
&admin=true
```

Ke tan cong biet message goc, MAC goc va do dai key, nhung khong biet
noi dung secret key.

## Build HashPump

Chay tu thu muc HashPump:

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB4/tools/HashPump
g++ -std=c++11 -O2 main.cpp Extender.cpp MD4ex.cpp MD5ex.cpp SHA1.cpp SHA256.cpp SHA512ex.cpp -lcrypto -o HashPump
```

Kiem tra tool:

```bash
./HashPump -h
```

Neu OpenSSL 3.x in warning `deprecated`, co the bo qua neu build van thanh cong.

## Chay attack

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB4/tools/HashPump
./HashPump \
  -s c8e31557f57905134ab15990e56d8ab6f60ca1c8d6a4517908d57867f3327519 \
  -d "user=guest&role=user" \
  -k 14 \
  -a "&admin=true"
```

Y nghia tham so:

```text
-s  MAC/signature goc da biet
-d  message goc da biet
-k  do dai secret key tinh bang byte
-a  du lieu muon noi them vao message
```

Luu output vao file result:

```bash
./HashPump \
  -s c8e31557f57905134ab15990e56d8ab6f60ca1c8d6a4517908d57867f3327519 \
  -d "user=guest&role=user" \
  -k 14 \
  -a "&admin=true" \
  > ../../attacks/length_extension/result.txt
```

## Ket qua

Noi dung `result.txt` gom 2 dong:

