#include "pq_core.h"

#include <oqs/oqs.h>

#include <cstring>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <memory>
#include <algorithm>

namespace pq {

// =====================================================================
// File I/O
// =====================================================================
Bytes read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + path);
    std::ostringstream ss; ss << f.rdbuf();
    const std::string& s = ss.str();
    return Bytes(s.begin(), s.end());
}
void write_file(const std::string& path, const Bytes& b) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + path);
    if (!b.empty()) f.write(reinterpret_cast<const char*>(b.data()), b.size());
}
void write_file(const std::string& path, const std::string& s) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + path);
    f.write(s.data(), s.size());
}

// =====================================================================
// Hex / Base64
// =====================================================================
static const char* HEX = "0123456789abcdef";
std::string hex_encode(const Bytes& b) {
    std::string r; r.reserve(b.size() * 2);
    for (auto x : b) { r.push_back(HEX[x >> 4]); r.push_back(HEX[x & 0xF]); }
    return r;
}
Bytes hex_decode(const std::string& s) {
    auto val = [](char c)->int{
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        return -1;
    };
    Bytes r;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        int hi = val(s[i]), lo = val(s[i+1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("invalid hex");
        r.push_back((uint8_t)((hi << 4) | lo));
    }
    return r;
}

// RFC 4648 base64 (no line breaks for encode; b64_encode used only for raw inline).
static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string b64_encode(const Bytes& b) {
    std::string r;
    int v = 0, bits = -6;
    for (uint8_t c : b) {
        v = (v << 8) | c; bits += 8;
        while (bits >= 0) { r.push_back(B64[(v >> bits) & 0x3F]); bits -= 6; }
    }
    if (bits > -6) r.push_back(B64[((v << 8) >> (bits + 8)) & 0x3F]);
    while (r.size() % 4) r.push_back('=');
    return r;
}
Bytes b64_decode(const std::string& s) {
    static int8_t T[256]; static bool init = false;
    if (!init) {
        std::fill(std::begin(T), std::end(T), (int8_t)-1);
        for (int i = 0; i < 64; ++i) T[(uint8_t)B64[i]] = (int8_t)i;
        init = true;
    }
    Bytes r;
    int v = 0, bits = -8;
    for (char c : s) {
        if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        int8_t d = T[(uint8_t)c];
        if (d < 0) throw std::runtime_error("invalid base64");
        v = (v << 6) | d; bits += 6;
        if (bits >= 0) { r.push_back((uint8_t)((v >> bits) & 0xFF)); bits -= 8; }
    }
    return r;
}

// =====================================================================
// PEM wrap (raw bytes → -----BEGIN <LABEL>----- block base64 -----END)
// ML-DSA/ML-KEM keys không có ASN.1 chuẩn ; ta dùng wrap riêng để ghi text-safe.
// =====================================================================
std::string pem_wrap(const std::string& label, const Bytes& der) {
    std::string b = b64_encode(der);
    std::ostringstream os;
    os << "-----BEGIN " << label << "-----\n";
    for (size_t i = 0; i < b.size(); i += 64)
        os << b.substr(i, 64) << "\n";
    os << "-----END " << label << "-----\n";
    return os.str();
}
Bytes pem_unwrap(const std::string& label, const std::string& pem) {
    std::string hdr = "-----BEGIN " + label + "-----";
    std::string ftr = "-----END "   + label + "-----";
    auto a = pem.find(hdr);
    auto b = pem.find(ftr);
    if (a == std::string::npos || b == std::string::npos || b < a)
        throw std::runtime_error("Malformed PEM: expected " + label);
    std::string body = pem.substr(a + hdr.size(), b - (a + hdr.size()));
    return b64_decode(body);
}

// =====================================================================
// ML-DSA  (liboqs OQS_SIG_alg_ml_dsa_*)
// =====================================================================
const char* dsa_name(DsaParam p) {
    switch (p) {
        case DsaParam::ML_DSA_44: return OQS_SIG_alg_ml_dsa_44;
        case DsaParam::ML_DSA_65: return OQS_SIG_alg_ml_dsa_65;
        case DsaParam::ML_DSA_87: return OQS_SIG_alg_ml_dsa_87;
    }
    throw std::runtime_error("Unknown DsaParam");
}
DsaParam dsa_from_string(const std::string& s) {
    if (s == "mldsa-44" || s == "ML-DSA-44") return DsaParam::ML_DSA_44;
    if (s == "mldsa-65" || s == "ML-DSA-65") return DsaParam::ML_DSA_65;
    if (s == "mldsa-87" || s == "ML-DSA-87") return DsaParam::ML_DSA_87;
    throw std::runtime_error("Unknown ML-DSA: " + s);
}
static std::string dsa_label(DsaParam p, bool priv) {
    std::string b = (p == DsaParam::ML_DSA_44 ? "ML-DSA-44"
                   : p == DsaParam::ML_DSA_65 ? "ML-DSA-65" : "ML-DSA-87");
    return b + (priv ? " PRIVATE KEY" : " PUBLIC KEY");
}

namespace {
struct SigRAII {
    OQS_SIG* s;
    explicit SigRAII(const char* alg) : s(OQS_SIG_new(alg)) {
        if (!s) throw std::runtime_error("OQS_SIG_new failed (build liboqs có bật alg?): " + std::string(alg));
    }
    ~SigRAII() { if (s) OQS_SIG_free(s); }
};
struct KemRAII {
    OQS_KEM* k;
    explicit KemRAII(const char* alg) : k(OQS_KEM_new(alg)) {
        if (!k) throw std::runtime_error("OQS_KEM_new failed: " + std::string(alg));
    }
    ~KemRAII() { if (k) OQS_KEM_free(k); }
};

// Tìm DsaParam tương ứng với độ dài public key — dùng khi load PEM mà không biết
// algorithm trước (cert verify đã ghi rõ algorithm trong JSON).
} // anon

void mldsa_keygen(DsaParam p, const std::string& priv_path, const std::string& pub_path) {
    SigRAII s(dsa_name(p));
    Bytes pub(s.s->length_public_key), priv(s.s->length_secret_key);
    if (OQS_SIG_keypair(s.s, pub.data(), priv.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-DSA keypair generation failed");
    write_file(priv_path, pem_wrap(dsa_label(p, true),  priv));
    write_file(pub_path,  pem_wrap(dsa_label(p, false), pub));
}

// Đọc PEM thử lần lượt 3 ML-DSA label, trả param phù hợp + raw key bytes.
static std::pair<DsaParam, Bytes> load_dsa_pem(const std::string& path, bool want_priv) {
    auto bytes = read_file(path);
    std::string pem(bytes.begin(), bytes.end());
    for (auto p : {DsaParam::ML_DSA_44, DsaParam::ML_DSA_65, DsaParam::ML_DSA_87}) {
        std::string lbl = dsa_label(p, want_priv);
        if (pem.find("-----BEGIN " + lbl + "-----") != std::string::npos)
            return {p, pem_unwrap(lbl, pem)};
    }
    throw std::runtime_error("Not an ML-DSA " + std::string(want_priv ? "private" : "public") + " key PEM: " + path);
}

Bytes mldsa_sign(const std::string& priv_path, const Bytes& msg) {
    auto [p, priv] = load_dsa_pem(priv_path, /*want_priv=*/true);
    SigRAII s(dsa_name(p));
    if (priv.size() != s.s->length_secret_key)
        throw std::runtime_error("Private key length mismatch");
    Bytes sig(s.s->length_signature);
    size_t sig_len = 0;
    if (OQS_SIG_sign(s.s, sig.data(), &sig_len, msg.data(), msg.size(), priv.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-DSA sign failed");
    sig.resize(sig_len);
    return sig;
}

bool mldsa_verify(const std::string& pub_path, const Bytes& msg, const Bytes& sig) {
    try {
        auto [p, pub] = load_dsa_pem(pub_path, /*want_priv=*/false);
        SigRAII s(dsa_name(p));
        if (pub.size() != s.s->length_public_key) return false;
        return OQS_SIG_verify(s.s, msg.data(), msg.size(), sig.data(), sig.size(), pub.data())
               == OQS_SUCCESS;
    } catch (...) {
        return false;  // fail-closed, non-leaky
    }
}

// =====================================================================
// ML-KEM  (liboqs OQS_KEM_alg_ml_kem_*)
// =====================================================================
const char* kem_name(KemParam p) {
    switch (p) {
        case KemParam::ML_KEM_512:  return OQS_KEM_alg_ml_kem_512;
        case KemParam::ML_KEM_768:  return OQS_KEM_alg_ml_kem_768;
        case KemParam::ML_KEM_1024: return OQS_KEM_alg_ml_kem_1024;
    }
    throw std::runtime_error("Unknown KemParam");
}
KemParam kem_from_string(const std::string& s) {
    if (s == "mlkem-512"  || s == "ML-KEM-512")  return KemParam::ML_KEM_512;
    if (s == "mlkem-768"  || s == "ML-KEM-768")  return KemParam::ML_KEM_768;
    if (s == "mlkem-1024" || s == "ML-KEM-1024") return KemParam::ML_KEM_1024;
    throw std::runtime_error("Unknown ML-KEM: " + s);
}
static std::string kem_label(KemParam p, bool priv) {
    std::string b = (p == KemParam::ML_KEM_512  ? "ML-KEM-512"
                   : p == KemParam::ML_KEM_768  ? "ML-KEM-768" : "ML-KEM-1024");
    return b + (priv ? " PRIVATE KEY" : " PUBLIC KEY");
}

void mlkem_keygen(KemParam p, const std::string& priv_path, const std::string& pub_path) {
    KemRAII k(kem_name(p));
    Bytes pub(k.k->length_public_key), priv(k.k->length_secret_key);
    if (OQS_KEM_keypair(k.k, pub.data(), priv.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM keypair generation failed");
    write_file(priv_path, pem_wrap(kem_label(p, true),  priv));
    write_file(pub_path,  pem_wrap(kem_label(p, false), pub));
}

static std::pair<KemParam, Bytes> load_kem_pem(const std::string& path, bool want_priv) {
    auto bytes = read_file(path);
    std::string pem(bytes.begin(), bytes.end());
    for (auto p : {KemParam::ML_KEM_512, KemParam::ML_KEM_768, KemParam::ML_KEM_1024}) {
        std::string lbl = kem_label(p, want_priv);
        if (pem.find("-----BEGIN " + lbl + "-----") != std::string::npos)
            return {p, pem_unwrap(lbl, pem)};
    }
    throw std::runtime_error("Not an ML-KEM " + std::string(want_priv ? "private" : "public") + " key PEM: " + path);
}

void mlkem_encaps(const std::string& pub_path, const std::string& ct_path, const std::string& ss_path) {
    auto [p, pub] = load_kem_pem(pub_path, /*want_priv=*/false);
    KemRAII k(kem_name(p));
    if (pub.size() != k.k->length_public_key)
        throw std::runtime_error("Public key length mismatch");
    Bytes ct(k.k->length_ciphertext), ss(k.k->length_shared_secret);
    if (OQS_KEM_encaps(k.k, ct.data(), ss.data(), pub.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM encaps failed");
    write_file(ct_path, ct);
    write_file(ss_path, ss);
}

void mlkem_decaps(const std::string& priv_path, const std::string& ct_path, const std::string& ss_path) {
    auto [p, priv] = load_kem_pem(priv_path, /*want_priv=*/true);
    KemRAII k(kem_name(p));
    if (priv.size() != k.k->length_secret_key)
        throw std::runtime_error("Private key length mismatch");
    Bytes ct = read_file(ct_path);
    if (ct.size() != k.k->length_ciphertext)
        throw std::runtime_error("Ciphertext length mismatch");
    Bytes ss(k.k->length_shared_secret);
    if (OQS_KEM_decaps(k.k, ss.data(), ct.data(), priv.data()) != OQS_SUCCESS)
        throw std::runtime_error("ML-KEM decaps failed");
    write_file(ss_path, ss);
}

} // namespace pq
