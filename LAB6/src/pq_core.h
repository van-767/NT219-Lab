// Lab 6 — Post-Quantum core: ML-DSA + ML-KEM qua liboqs.
// Dùng chung cho 2 CLI (MLDSA, MLKEM) và lớp C API export DLL.
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace pq {

using Bytes = std::vector<uint8_t>;

// ===================================================================
// ML-DSA (Module-Lattice Digital Signature Algorithm) — FIPS 204
// ===================================================================
enum class DsaParam { ML_DSA_44, ML_DSA_65, ML_DSA_87 };

const char* dsa_name(DsaParam p);                   // tên liboqs
DsaParam    dsa_from_string(const std::string& s);  // "mldsa-44" | "mldsa-65" | "mldsa-87"

// Sinh cặp khoá ML-DSA, ghi PEM-style (base64-wrap) ra file.
void mldsa_keygen(DsaParam p, const std::string& priv_path, const std::string& pub_path);

// Ký detached. Trả về raw signature bytes.
Bytes mldsa_sign(const std::string& priv_path, const Bytes& msg);

// Verify. Trả về true/false. Fail-closed, không leak chi tiết.
bool mldsa_verify(const std::string& pub_path, const Bytes& msg, const Bytes& sig);

// ===================================================================
// ML-KEM (Module-Lattice Key Encapsulation Mechanism) — FIPS 203
// ===================================================================
enum class KemParam { ML_KEM_512, ML_KEM_768, ML_KEM_1024 };

const char* kem_name(KemParam p);
KemParam    kem_from_string(const std::string& s);  // "mlkem-512" | "mlkem-768" | "mlkem-1024"

void mlkem_keygen(KemParam p, const std::string& priv_path, const std::string& pub_path);

// Encapsulation: sender input pubkey, output (ciphertext, shared_secret).
void mlkem_encaps(const std::string& pub_path,
                  const std::string& ct_path,
                  const std::string& ss_path);

// Decapsulation: receiver input (privkey, ciphertext), output shared_secret.
// Throws nếu ciphertext invalid hoặc kích thước sai.
void mlkem_decaps(const std::string& priv_path,
                  const std::string& ct_path,
                  const std::string& ss_path);

// ===================================================================
// Helpers
// ===================================================================
Bytes read_file(const std::string& path);
void  write_file(const std::string& path, const Bytes& b);
void  write_file(const std::string& path, const std::string& s);

std::string hex_encode(const Bytes& b);
Bytes       hex_decode(const std::string& s);
std::string b64_encode(const Bytes& b);
Bytes       b64_decode(const std::string& s);

// PEM-style wrap cho raw key bytes (vì ML-DSA/ML-KEM không có ASN.1 chuẩn).
std::string pem_wrap(const std::string& label, const Bytes& der);
Bytes       pem_unwrap(const std::string& label, const std::string& pem);

} // namespace pq
