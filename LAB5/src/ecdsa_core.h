// Lab 5 — ECDSA core (P-256 mặc định, P-384 tùy chọn). Dùng chung cho CLI + DLL.
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace ecdsa {

using Bytes = std::vector<uint8_t>;

enum class Curve { P256, P384 };
enum class KeyFormat { PEM, DER };
enum class SigEncoding { Raw, DER, Base64 };  // "raw" = IEEE P1363 r||s; "der" = ASN.1; "base64" = base64(der)

Curve       curve_from_string(const std::string& s);   // "ecdsa-p256" | "ecdsa-p384" | "p256" | "p384"
const char* curve_to_string(Curve c);
KeyFormat   keyformat_from_string(const std::string& s);
SigEncoding sigenc_from_string(const std::string& s);

// Key generation. Throws std::runtime_error trên lỗi.
void keygen(Curve curve,
            const std::string& priv_path,
            const std::string& pub_path,
            KeyFormat fmt);

// Sign message bytes bằng SHA-256 (P-256) hoặc SHA-384 (P-384, nếu hash_override rỗng).
// hash_override: "sha256" hoặc "sha384" — nếu rỗng dùng theo curve.
Bytes sign_bytes(const std::string& priv_path,
                 const Bytes& msg,
                 const std::string& hash_override,
                 SigEncoding enc);

// Verify. Trả về true/false. Không leak chi tiết lỗi.
bool verify_bytes(const std::string& pub_path,
                  const Bytes& msg,
                  const Bytes& sig,
                  const std::string& hash_override,
                  SigEncoding enc);

// Helpers
Bytes read_file(const std::string& path);
void  write_file(const std::string& path, const Bytes& data);
void  write_file(const std::string& path, const std::string& s);

std::string hex_encode(const Bytes& b);
Bytes       hex_decode(const std::string& s);
std::string b64_encode(const Bytes& b);
Bytes       b64_decode(const std::string& s);

} // namespace ecdsa
