// Lab 5 — RSA-PSS core (3072-bit mặc định, SHA-256, salt = hashLen).
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace rsapss {

using Bytes = std::vector<uint8_t>;

enum class KeyFormat { PEM, DER };
enum class SigEncoding { Raw, Base64 };   // RSA-PSS sig là số nguyên độ dài k = ceil(modBits/8), không có "DER" riêng.

KeyFormat   keyformat_from_string(const std::string& s);
SigEncoding sigenc_from_string(const std::string& s);

// bits: 3072 (mặc định) hoặc 4096. <3072 sẽ bị từ chối theo spec Lab 3/5.
void keygen(int bits,
            const std::string& priv_path,
            const std::string& pub_path,
            KeyFormat fmt);

// hash_name: "sha256" mặc định; salt_len = -1 nghĩa là hashLen (đúng spec); 0 = không salt (test only).
Bytes sign_bytes(const std::string& priv_path,
                 const Bytes& msg,
                 const std::string& hash_name,
                 int salt_len,
                 SigEncoding enc);

bool verify_bytes(const std::string& pub_path,
                  const Bytes& msg,
                  const Bytes& sig,
                  const std::string& hash_name,
                  int salt_len,
                  SigEncoding enc);

// Helpers (giống ecdsa_core nhưng namespace riêng để dùng độc lập trong cli).
Bytes read_file(const std::string& path);
void  write_file(const std::string& path, const Bytes& data);
void  write_file(const std::string& path, const std::string& s);
std::string hex_encode(const Bytes& b);
std::string b64_encode(const Bytes& b);
Bytes       b64_decode(const std::string& s);

} // namespace rsapss
