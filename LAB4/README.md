# Lab 4 — Hashing, PKI, and Practical Attacks

NT219 — Mật mã ứng dụng — UIT.
Lab 4 chia thành 4 task độc lập, mỗi task có folder + README riêng.

## Cấu trúc

```
LAB4/
├── task1_hashing/              Task 1 (Hash CLI) + Task 5 (Performance)
│   ├── src/                    hash_core, hashtool_cli, c_api
│   ├── gui/hash_gui.py         PySide6 GUI
│   ├── tests/kat_vectors.json  1662 NIST CAVP vectors
│   ├── scripts/run_bench.*     auto benchmark
│   ├── bin/{windows,linux}/    binary
│   ├── logs/{windows,linux}/   CSV output
│   ├── CMakeLists.txt
│   └── README.md
│
├── task2_pki_tls/              Task 2 (X.509 + TLS deploy)
│   ├── cert/                   cert ZeroSSL (3 file)
│   ├── nginx/nginx.conf        config TLS 1.2/1.3
│   ├── parse_cert.sh           extract 11 field cert
│   ├── parse_output.txt        output parse
│   ├── tls_handshake.txt       output openssl s_client
│   ├── screenshots/            5 ảnh bằng chứng
│   └── README.md
│
├── attacks/
│   ├── md5_collision/          Task 3 (HashClash demo)
│   │   ├── program1.cpp, program2.cpp
│   │   ├── collision1.cpp, collision2.cpp
│   │   ├── md5_result.txt, sha256_result.txt
│   │   └── README.md
│   │
│   └── length_extension/       Task 4 (HashPump demo)
│       ├── result.txt
│       └── README.md
│
└── README.md                   (file này)
```

## Scope đã cài đặt

| # | Task | Folder | Output chính |
|---|------|--------|--------------|
| 1 | Hash CLI (SHA-2/3/SHAKE) | `task1_hashing/` | hashtool.exe + KAT 1662 PASS |
| 2 | X.509 parse + TLS deploy | `task2_pki_tls/` | cert ZeroSSL + HTTPS deployed VPS |
| 3 | MD5 collision demo | `attacks/md5_collision/` | 2 file C++ cùng MD5 khác SHA-256 |
| 4 | Length-extension attack | `attacks/length_extension/` | Forge MAC SHA-256 không biết key |
| 5 | Performance benchmark | gộp trong Task 1 | CSV 4 algo × 4 size × 2 OS |

## Hướng dẫn nhanh từng task

### Task 1 + 5 — Hash CLI & Benchmark

```bash
cd task1_hashing

# Build
cmake -B build -S . -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++
cmake --build build -j

# Test
./bin/windows/hashtool.exe kat --kat tests/kat_vectors.json
# → Summary: 1662 passed, 0 failed, 1662 total.

# Benchmark (Windows: double-click .bat / Linux: bash .sh)
./scripts/run_bench.bat
```

Chi tiết: [`task1_hashing/README.md`](task1_hashing/README.md)

### Task 2 — TLS Deployment

Web đã deploy production tại `https://nt219-zerotrust.duckdns.org`
(VPS + Docker + nginx). Verify nhanh từ bất kỳ máy nào:

```bash
# Parse cert offline
./parse_cert.sh cert/certificate.crt > parse_output.txt

# Verify handshake real qua Internet
openssl s_client -connect nt219-zerotrust.duckdns.org:443 \
    -servername nt219-zerotrust.duckdns.org
```

Chi tiết: [`task2_pki_tls/README.md`](task2_pki_tls/README.md)

### Task 3 — MD5 Collision

Dùng [HashClash](https://github.com/cr-marcstevens/hashclash) tạo 2 file
C++ có cùng MD5 nhưng khác SHA-256.

```bash
cd attacks/md5_collision
md5sum    collision1.cpp collision2.cpp    # → 2 hash GIỐNG
sha256sum collision1.cpp collision2.cpp    # → 2 hash KHÁC
```

Chi tiết: [`attacks/md5_collision/README.md`](attacks/md5_collision/README.md)

### Task 4 — Length-Extension

Dùng [HashPump](https://github.com/bwall/HashPump) forge MAC dạng
`SHA-256(key || msg)` mà không biết `key`.

Chi tiết: [`attacks/length_extension/README.md`](attacks/length_extension/README.md)