# Lab 4 — MD5 Chosen-Prefix Collision Demo

Task nay lam theo huong khong di duong tat: dung HashClash `cpc.sh` de tao
chosen-prefix collision. Cach nay lau hon `md5_fastcoll`, nhung cho phep minh
dung 2 chuong trinh C++ khac nhau lam input.

## Muc tieu

Tao 2 file khac nhau nhung co cung MD5 digest:

```text
MD5(program1.cpp.coll) = MD5(program2.cpp.coll)
```

Sau do chung minh:

- 2 file khac noi dung
- MD5 giong nhau
- SHA-256 khac nhau

## Chuan bi 2 chuong trinh input

`program1.cpp`:

```cpp
#include <iostream>
#include <string>

int main() {
    std::string role = "user";
    std::cout << "MD5 collision demo - Program 1\n";
    std::cout << "Current role: " << role << "\n";
    return 0;
}
```

`program2.cpp`:

```cpp
#include <iostream>
#include <string>

int main() {
    std::string role = "admin";
    std::cout << "MD5 collision demo - Program 2\n";
    std::cout << "Current role: " << role << "\n";
    return 0;
}
```

Hai file nay la 2 chuong trinh C++ co ban, compile va chay duoc truoc khi tao
collision.

Kiem tra chuong trinh goc:

```bash
g++ program1.cpp -o program1
g++ program2.cpp -o program2
./program1
./program2
```

## Chay chosen-prefix collision

Chay ngay trong thu muc task:

```bash
cd ~/Study/LabVNLabVN/NT219-Lab/LAB4/attacks/md5_collision
../../tools/hashclash/scripts/cpc.sh program1.cpp program2.cpp
```

Qua trinh nay co the chay lau. Day la phan dung ban chat chosen-prefix
collision, khac voi `md5_fastcoll` chay nhanh.

Khi thanh cong, HashClash tao:

```text
program1.cpp.coll
program2.cpp.coll
```

## Doi ten file ket qua

```bash
cp program1.cpp.coll collision1.cpp
cp program2.cpp.coll collision2.cpp
```

Neu chi can chung minh collision, dung 2 file nay de hash la du.

## Kiem tra MD5 collision

Kiem tra MD5 giong nhau:

```bash
md5sum collision1.cpp collision2.cpp
```

Kiem tra 2 file khac nhau:

```bash
cmp -l collision1.cpp collision2.cpp
```

Kiem tra SHA-256 khac nhau:

```bash
sha256sum collision1.cpp collision2.cpp
```

## Luu output

```bash
md5sum collision1.cpp collision2.cpp > md5_result.txt
cmp -l collision1.cpp collision2.cpp > diff_result.txt
sha256sum collision1.cpp collision2.cpp > sha256_result.txt
```

File can dua vao report:

```text
program1.cpp
program2.cpp
collision1.cpp
collision2.cpp
md5_result.txt
diff_result.txt
sha256_result.txt
```

## Ghi chu ve compile

Output `.coll` cua HashClash co them collision bytes vao sau noi dung goc. Neu
can compile truc tiep file `.coll`, co the can xu ly them tuy cach bytes duoc
chen. Trong task nay, bang chung chinh la:

```text
2 file khac nhau + cung MD5 digest
```

Hai chuong trinh goc de chay demo:

```bash
g++ program1.cpp -o program1
g++ program2.cpp -o program2
./program1
./program2
```

Bang chung collision nam o `collision1.cpp` va `collision2.cpp`.

## Report

```text
Objective:
Demonstrate an MD5 chosen-prefix collision by generating two different files
from two different C++ programs with the same MD5 digest.

Method:
Two different C++ programs were prepared: program1.cpp and program2.cpp.
HashClash cpc.sh was used to perform a chosen-prefix collision attack using
these two programs as input files. The generated `.coll` files were renamed to
collision1.cpp and collision2.cpp. The files were checked with md5sum, cmp, and
sha256sum.

Commands:
../../tools/hashclash/scripts/cpc.sh program1.cpp program2.cpp
md5sum collision1.cpp collision2.cpp
cmp -l collision1.cpp collision2.cpp
sha256sum collision1.cpp collision2.cpp

Result:
collision1.cpp and collision2.cpp are different files, but they have the same
MD5 digest. Their SHA-256 digests are different.

Security note:
MD5 is broken for collision resistance. It must not be used for digital
signatures, certificates, or security-sensitive integrity checks. Use SHA-256,
SHA-3, or HMAC-SHA256 instead.
```
