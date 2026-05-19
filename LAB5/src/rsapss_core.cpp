#include "rsapss_core.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <fstream>
#include <stdexcept>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace rsapss {

static std::string ossl_err() {
    unsigned long e = ERR_peek_last_error();
    if (!e) return "";
    char buf[256]; ERR_error_string_n(e, buf, sizeof(buf));
    ERR_clear_error();
    return buf;
}
static void die(const std::string& w) {
    auto e = ossl_err();
    throw std::runtime_error(e.empty() ? w : (w + ": " + e));
}
static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return (char)std::tolower(c); });
    return s;
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
std::string b64_encode(const Bytes& b) {
    BIO* mem = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, mem);
    BIO_write(b64, b.data(), (int)b.size());
    BIO_flush(b64);
    BUF_MEM* bp = nullptr; BIO_get_mem_ptr(b64, &bp);
    std::string out(bp->data, bp->length);
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

KeyFormat keyformat_from_string(const std::string& s_in) {
    auto s = lower(s_in);
    if (s == "pem") return KeyFormat::PEM;
    if (s == "der") return KeyFormat::DER;
    throw std::runtime_error("Unsupported key format: " + s_in);
}
SigEncoding sigenc_from_string(const std::string& s_in) {
    auto s = lower(s_in);
    if (s == "raw") return SigEncoding::Raw;
    if (s == "base64" || s == "b64") return SigEncoding::Base64;
    throw std::runtime_error("Unsupported sig encoding: " + s_in + " (raw|base64)");
}

static const EVP_MD* md_from_name(const std::string& name) {
    auto s = lower(name);
    if (s.empty() || s == "sha256") return EVP_sha256();
    if (s == "sha384") return EVP_sha384();
    if (s == "sha512") return EVP_sha512();
    throw std::runtime_error("Unsupported hash: " + name);
}

void keygen(int bits, const std::string& priv_path,
            const std::string& pub_path, KeyFormat fmt) {
    if (bits < 3072) throw std::runtime_error("Key size must be ≥ 3072 bits (spec Lab 5)");

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) die("EVP_PKEY_CTX_new_id");
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); die("keygen_init"); }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx); die("set_keygen_bits");
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) { EVP_PKEY_CTX_free(ctx); die("EVP_PKEY_keygen"); }
    EVP_PKEY_CTX_free(ctx);

    BIO* bp = BIO_new_file(priv_path.c_str(), fmt == KeyFormat::PEM ? "w" : "wb");
    if (!bp) { EVP_PKEY_free(pkey); die("open priv"); }
    int ok = (fmt == KeyFormat::PEM)
        ? PEM_write_bio_PrivateKey(bp, pkey, nullptr, nullptr, 0, nullptr, nullptr)
        : i2d_PrivateKey_bio(bp, pkey);
    BIO_free(bp);
    if (!ok) { EVP_PKEY_free(pkey); die("write priv"); }

    BIO* bu = BIO_new_file(pub_path.c_str(), fmt == KeyFormat::PEM ? "w" : "wb");
    if (!bu) { EVP_PKEY_free(pkey); die("open pub"); }
    ok = (fmt == KeyFormat::PEM)
        ? PEM_write_bio_PUBKEY(bu, pkey)
        : i2d_PUBKEY_bio(bu, pkey);
    BIO_free(bu);
    EVP_PKEY_free(pkey);
    if (!ok) die("write pub");
}

static EVP_PKEY* load_priv(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw std::runtime_error("Cannot open private key: " + path);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) { BIO_reset(bio); pkey = d2i_PrivateKey_bio(bio, nullptr); }
    BIO_free(bio);
    if (!pkey) die("parse private key");
    return pkey;
}
static EVP_PKEY* load_pub(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "rb");
    if (!bio) throw std::runtime_error("Cannot open public key: " + path);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if (!pkey) { BIO_reset(bio); pkey = d2i_PUBKEY_bio(bio, nullptr); }
    BIO_free(bio);
    if (!pkey) die("parse public key");
    return pkey;
}

Bytes sign_bytes(const std::string& priv_path,
                 const Bytes& msg,
                 const std::string& hash_name,
                 int salt_len,
                 SigEncoding enc) {
    EVP_PKEY* pkey = load_priv(priv_path);
    const EVP_MD* md = md_from_name(hash_name);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); die("MD_CTX_new"); }

    Bytes sig;
    try {
        EVP_PKEY_CTX* pctx = nullptr;
        if (EVP_DigestSignInit(ctx, &pctx, md, nullptr, pkey) <= 0) die("DigestSignInit");
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0) die("set_pss_padding");
        int sl = (salt_len < 0) ? RSA_PSS_SALTLEN_DIGEST : salt_len;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, sl) <= 0) die("set_saltlen");
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) <= 0) die("set_mgf1_md");

        if (EVP_DigestSignUpdate(ctx, msg.data(), msg.size()) <= 0) die("DigestSignUpdate");
        size_t slen = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &slen) <= 0) die("DigestSignFinal(size)");
        sig.resize(slen);
        if (EVP_DigestSignFinal(ctx, sig.data(), &slen) <= 0) die("DigestSignFinal");
        sig.resize(slen);
    } catch (...) { EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey); throw; }

    EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);

    if (enc == SigEncoding::Base64) {
        std::string s = b64_encode(sig);
        return Bytes(s.begin(), s.end());
    }
    return sig;
}

bool verify_bytes(const std::string& pub_path,
                  const Bytes& msg,
                  const Bytes& sig,
                  const std::string& hash_name,
                  int salt_len,
                  SigEncoding enc) {
    EVP_PKEY* pkey = nullptr;
    try { pkey = load_pub(pub_path); } catch (...) { return false; }
    const EVP_MD* md = nullptr;
    try { md = md_from_name(hash_name); } catch (...) { EVP_PKEY_free(pkey); return false; }

    Bytes raw;
    try {
        if (enc == SigEncoding::Base64) {
            std::string s(sig.begin(), sig.end());
            raw = b64_decode(s);
        } else raw = sig;
    } catch (...) { EVP_PKEY_free(pkey); return false; }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }
    int rc = 0;
    EVP_PKEY_CTX* pctx = nullptr;
    if (EVP_DigestVerifyInit(ctx, &pctx, md, nullptr, pkey) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt_len < 0 ? RSA_PSS_SALTLEN_DIGEST : salt_len) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, md) > 0 &&
        EVP_DigestVerifyUpdate(ctx, msg.data(), msg.size()) > 0) {
        rc = EVP_DigestVerifyFinal(ctx, raw.data(), raw.size());
    }
    EVP_MD_CTX_free(ctx); EVP_PKEY_free(pkey);
    ERR_clear_error();
    return rc == 1;
}

} // namespace rsapss
