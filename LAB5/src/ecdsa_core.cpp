#include "ecdsa_core.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>

#include <fstream>
#include <stdexcept>
#include <cstring>
#include <cctype>
#include <algorithm>

namespace ecdsa {

// ─── small helpers ────────────────────────────────────────────────────────

static std::string ossl_err() {
    unsigned long e = ERR_peek_last_error();
    if (!e) return "";
    char buf[256]; ERR_error_string_n(e, buf, sizeof(buf));
    ERR_clear_error();
    return buf;
}
static void die(const std::string& what) {
    auto e = ossl_err();
    throw std::runtime_error(e.empty() ? what : (what + ": " + e));
}

Bytes read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open input: " + path);
    return Bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
void write_file(const std::string& path, const Bytes& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open output: " + path);
    if (!data.empty()) f.write((const char*)data.data(), (std::streamsize)data.size());
}
void write_file(const std::string& path, const std::string& s) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open output: " + path);
    f.write(s.data(), (std::streamsize)s.size());
}

static const char* HEX = "0123456789abcdef";
std::string hex_encode(const Bytes& b) {
    std::string out; out.resize(b.size() * 2);
    for (size_t i = 0; i < b.size(); ++i) {
        out[2*i]   = HEX[b[i] >> 4];
        out[2*i+1] = HEX[b[i] & 0xF];
    }
    return out;
}
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
Bytes hex_decode(const std::string& s) {
    std::string t; t.reserve(s.size());
    for (char c : s) if (!std::isspace((unsigned char)c)) t.push_back(c);
    if (t.size() % 2) throw std::runtime_error("Hex length must be even");
    Bytes out(t.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = hexval(t[2*i]), lo = hexval(t[2*i+1]);
        if (hi < 0 || lo < 0) throw std::runtime_error("Invalid hex character");
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return out;
}
std::string b64_encode(const Bytes& b) {
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, b.data(), (int)b.size());
    BIO_flush(b64);
    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}
Bytes b64_decode(const std::string& s) {
    BIO* mem = BIO_new_mem_buf(s.data(), (int)s.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    Bytes out(s.size());
    int n = BIO_read(b64, out.data(), (int)out.size());
    BIO_free_all(b64);
    if (n < 0) throw std::runtime_error("Invalid base64");
    out.resize(n);
    return out;
}

// ─── enum parsing ─────────────────────────────────────────────────────────

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}
Curve curve_from_string(const std::string& s_in) {
    auto s = lower(s_in);
    if (s == "p256" || s == "ecdsa-p256" || s == "secp256r1" || s == "prime256v1") return Curve::P256;
    if (s == "p384" || s == "ecdsa-p384" || s == "secp384r1") return Curve::P384;
    throw std::runtime_error("Unsupported curve: " + s_in + " (use ecdsa-p256 or ecdsa-p384)");
}
const char* curve_to_string(Curve c) {
    return c == Curve::P256 ? "ecdsa-p256" : "ecdsa-p384";
}
KeyFormat keyformat_from_string(const std::string& s_in) {
    auto s = lower(s_in);
    if (s == "pem") return KeyFormat::PEM;
    if (s == "der") return KeyFormat::DER;
    throw std::runtime_error("Unsupported key format: " + s_in + " (pem|der)");
}
SigEncoding sigenc_from_string(const std::string& s_in) {
    auto s = lower(s_in);
    if (s == "raw")    return SigEncoding::Raw;
    if (s == "der")    return SigEncoding::DER;
    if (s == "base64" || s == "b64") return SigEncoding::Base64;
    throw std::runtime_error("Unsupported sig encoding: " + s_in + " (raw|der|base64)");
}

// ─── key I/O ──────────────────────────────────────────────────────────────

static int curve_nid(Curve c) {
    return c == Curve::P256 ? NID_X9_62_prime256v1 : NID_secp384r1;
}
static const EVP_MD* default_md(Curve c) {
    return c == Curve::P256 ? EVP_sha256() : EVP_sha384();
}
static const EVP_MD* md_from_name(const std::string& name, Curve c) {
    if (name.empty()) return default_md(c);
    auto s = lower(name);
    if (s == "sha256") return EVP_sha256();
    if (s == "sha384") return EVP_sha384();
    if (s == "sha512") return EVP_sha512();
    throw std::runtime_error("Unsupported hash: " + name);
}

static EVP_PKEY* gen_keypair(Curve c) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) die("EVP_PKEY_CTX_new_id");
    if (EVP_PKEY_keygen_init(pctx) <= 0) { EVP_PKEY_CTX_free(pctx); die("keygen_init"); }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid(c)) <= 0) {
        EVP_PKEY_CTX_free(pctx); die("set_curve_nid");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) { EVP_PKEY_CTX_free(pctx); die("EVP_PKEY_keygen"); }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static void save_keypair(EVP_PKEY* pkey,
                         const std::string& priv_path,
                         const std::string& pub_path,
                         KeyFormat fmt) {
    BIO* bp = BIO_new_file(priv_path.c_str(), fmt == KeyFormat::PEM ? "w" : "wb");
    if (!bp) die("open priv file");
    int ok = (fmt == KeyFormat::PEM)
        ? PEM_write_bio_PrivateKey(bp, pkey, nullptr, nullptr, 0, nullptr, nullptr)
        : i2d_PrivateKey_bio(bp, pkey);
    BIO_free(bp);
    if (!ok) die("write priv");

    BIO* bu = BIO_new_file(pub_path.c_str(), fmt == KeyFormat::PEM ? "w" : "wb");
    if (!bu) die("open pub file");
    ok = (fmt == KeyFormat::PEM)
        ? PEM_write_bio_PUBKEY(bu, pkey)
        : i2d_PUBKEY_bio(bu, pkey);
    BIO_free(bu);
    if (!ok) die("write pub");
}

static EVP_PKEY* load_priv(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw std::runtime_error("Cannot open private key: " + path);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) { BIO_reset(bio); pkey = d2i_PrivateKey_bio(bio, nullptr); }
    BIO_free(bio);
    if (!pkey) die("Failed to parse private key");
    return pkey;
}
static EVP_PKEY* load_pub(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw std::runtime_error("Cannot open public key: " + path);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) { BIO_reset(bio); pkey = d2i_PUBKEY_bio(bio, nullptr); }
    BIO_free(bio);
    if (!pkey) die("Failed to parse public key");
    return pkey;
}

void keygen(Curve curve, const std::string& priv_path,
            const std::string& pub_path, KeyFormat fmt) {
    EVP_PKEY* pkey = gen_keypair(curve);
    try { save_keypair(pkey, priv_path, pub_path, fmt); }
    catch (...) { EVP_PKEY_free(pkey); throw; }
    EVP_PKEY_free(pkey);
}

// ─── DER ↔ raw (P1363) signature conversion ───────────────────────────────

static size_t order_bytes_for_pkey(EVP_PKEY* pkey) {
    // Get curve order length in bytes.
    EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec) die("not an EC key");
    const EC_GROUP* g = EC_KEY_get0_group(ec);
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(g, order, nullptr);
    size_t nlen = (BN_num_bits(order) + 7) / 8;
    BN_free(order);
    EC_KEY_free(ec);
    return nlen;
}

static Bytes der_to_raw(const Bytes& der, size_t nlen) {
    const unsigned char* p = der.data();
    ECDSA_SIG* s = d2i_ECDSA_SIG(nullptr, &p, (long)der.size());
    if (!s) die("malformed DER signature");
    const BIGNUM *r, *ss;
    ECDSA_SIG_get0(s, &r, &ss);
    Bytes out(2 * nlen, 0);
    BN_bn2binpad(r,  out.data(),         (int)nlen);
    BN_bn2binpad(ss, out.data() + nlen,  (int)nlen);
    ECDSA_SIG_free(s);
    return out;
}
static Bytes raw_to_der(const Bytes& raw, size_t nlen) {
    if (raw.size() != 2 * nlen) throw std::runtime_error("Raw sig size mismatch");
    ECDSA_SIG* s = ECDSA_SIG_new();
    BIGNUM* r  = BN_bin2bn(raw.data(),         (int)nlen, nullptr);
    BIGNUM* ss = BN_bin2bn(raw.data() + nlen,  (int)nlen, nullptr);
    if (!ECDSA_SIG_set0(s, r, ss)) { ECDSA_SIG_free(s); die("ECDSA_SIG_set0"); }
    unsigned char* p = nullptr;
    int len = i2d_ECDSA_SIG(s, &p);
    if (len <= 0) { ECDSA_SIG_free(s); die("i2d_ECDSA_SIG"); }
    Bytes out(p, p + len);
    OPENSSL_free(p);
    ECDSA_SIG_free(s);
    return out;
}

// ─── sign / verify ────────────────────────────────────────────────────────

Bytes sign_bytes(const std::string& priv_path,
                 const Bytes& msg,
                 const std::string& hash_override,
                 SigEncoding enc) {
    EVP_PKEY* pkey = load_priv(priv_path);

    Curve c = Curve::P256;
    {
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
        if (!ec) { EVP_PKEY_free(pkey); die("not EC"); }
        int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
        EC_KEY_free(ec);
        if (nid == NID_secp384r1) c = Curve::P384;
        else if (nid != NID_X9_62_prime256v1) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Only P-256 / P-384 supported");
        }
    }
    const EVP_MD* md = md_from_name(hash_override, c);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); die("EVP_MD_CTX_new"); }

    size_t slen = 0;
    Bytes der_sig;
    try {
        if (EVP_DigestSignInit(ctx, nullptr, md, nullptr, pkey) <= 0) die("DigestSignInit");
        if (EVP_DigestSignUpdate(ctx, msg.data(), msg.size()) <= 0)   die("DigestSignUpdate");
        if (EVP_DigestSignFinal(ctx, nullptr, &slen) <= 0)            die("DigestSignFinal(size)");
        der_sig.resize(slen);
        if (EVP_DigestSignFinal(ctx, der_sig.data(), &slen) <= 0)     die("DigestSignFinal");
        der_sig.resize(slen);
    } catch (...) {
        EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey); throw;
    }
    EVP_MD_CTX_free(ctx);

    size_t nlen = order_bytes_for_pkey(pkey);
    EVP_PKEY_free(pkey);

    switch (enc) {
        case SigEncoding::DER: return der_sig;
        case SigEncoding::Raw: return der_to_raw(der_sig, nlen);
        case SigEncoding::Base64: {
            std::string s = b64_encode(der_sig);
            return Bytes(s.begin(), s.end());
        }
    }
    return der_sig;
}

bool verify_bytes(const std::string& pub_path,
                  const Bytes& msg,
                  const Bytes& sig,
                  const std::string& hash_override,
                  SigEncoding enc) {
    EVP_PKEY* pkey = nullptr;
    try { pkey = load_pub(pub_path); }
    catch (...) { return false; }

    Curve c = Curve::P256;
    {
        EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
        if (!ec) { EVP_PKEY_free(pkey); return false; }
        int nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(ec));
        EC_KEY_free(ec);
        if (nid == NID_secp384r1) c = Curve::P384;
        else if (nid != NID_X9_62_prime256v1) { EVP_PKEY_free(pkey); return false; }
    }
    const EVP_MD* md = nullptr;
    try { md = md_from_name(hash_override, c); }
    catch (...) { EVP_PKEY_free(pkey); return false; }

    // Normalise to DER for OpenSSL verify.
    Bytes der_sig;
    try {
        if (enc == SigEncoding::DER) {
            der_sig = sig;
        } else if (enc == SigEncoding::Raw) {
            size_t nlen = order_bytes_for_pkey(pkey);
            der_sig = raw_to_der(sig, nlen);
        } else { // Base64
            std::string s(sig.begin(), sig.end());
            der_sig = b64_decode(s);
        }
    } catch (...) { EVP_PKEY_free(pkey); return false; }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }
    int rc = 0;
    if (EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pkey) > 0 &&
        EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()) > 0) {
        rc = EVP_DigestVerifyFinal(ctx, der_sig.data(), der_sig.size());
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    ERR_clear_error();
    return rc == 1;
}

} // namespace ecdsa
