#include "rsa_core.h"

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <numeric>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <cstring>

#include "rsa.h"
#include "osrng.h"
#include "base64.h"
#include "hex.h"
#include "files.h"
#include "filters.h"
#include "sha.h"
#include "aes.h"
#include "gcm.h"
#include "queue.h"
#include "secblock.h"

using namespace CryptoPP;
namespace rsa_lab {

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------
static std::string b64_encode(const std::string& in) {
    std::string out;
    StringSource(in, true, new Base64Encoder(new StringSink(out), false));
    return out;
}
static std::string b64_decode(const std::string& in) {
    std::string out;
    StringSource(in, true, new Base64Decoder(new StringSink(out)));
    return out;
}
static std::string b64_encode(const std::uint8_t* p, std::size_t n) {
    return b64_encode(std::string(reinterpret_cast<const char*>(p), n));
}
static std::vector<std::uint8_t> as_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}
static std::string as_string(const std::vector<std::uint8_t>& v) {
    return std::string(v.begin(), v.end());
}
static std::string read_file(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + p);
    std::ostringstream ss; ss << f.rdbuf();
    return ss.str();
}
static void write_file(const std::string& p, const std::string& data) {
    std::ofstream f(p, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot write: " + p);
    f.write(data.data(), data.size());
}

// ---------------------------------------------------------------------------
// PEM (PKCS#1) read/write — Crypto++ does not ship PEM support in core build.
// ---------------------------------------------------------------------------
static const char* PEM_PRIV_HDR = "-----BEGIN RSA PRIVATE KEY-----";
static const char* PEM_PRIV_FTR = "-----END RSA PRIVATE KEY-----";
static const char* PEM_PUB_HDR  = "-----BEGIN RSA PUBLIC KEY-----";
static const char* PEM_PUB_FTR  = "-----END RSA PUBLIC KEY-----";

static std::string der_to_pem(const std::string& der, bool is_priv) {
    std::string b64;
    StringSource(der, true, new Base64Encoder(new StringSink(b64), true, 64));
    std::string h = is_priv ? PEM_PRIV_HDR : PEM_PUB_HDR;
    std::string f = is_priv ? PEM_PRIV_FTR : PEM_PUB_FTR;
    return h + "\n" + b64 + f + "\n";
}

static std::string pem_to_der(const std::string& pem, bool is_priv) {
    std::string h = is_priv ? PEM_PRIV_HDR : PEM_PUB_HDR;
    std::string f = is_priv ? PEM_PRIV_FTR : PEM_PUB_FTR;
    auto a = pem.find(h);
    auto b = pem.find(f);
    if (a == std::string::npos || b == std::string::npos || b <= a)
        throw std::runtime_error("Malformed PEM: missing header/footer");
    std::string body = pem.substr(a + h.size(), b - (a + h.size()));
    // Strip whitespace/newlines
    std::string clean;
    clean.reserve(body.size());
    for (char c : body) if (c != '\n' && c != '\r' && c != ' ' && c != '\t') clean.push_back(c);
    std::string der;
    try {
        StringSource(clean, true, new Base64Decoder(new StringSink(der)));
    } catch (const Exception& e) {
        throw std::runtime_error(std::string("Malformed PEM base64: ") + e.what());
    }
    return der;
}

static void save_priv_pem(const RSA::PrivateKey& k, const std::string& path) {
    ByteQueue q; k.DEREncodePrivateKey(q);
    std::string der; StringSink s(der); q.CopyTo(s);
    write_file(path, der_to_pem(der, true));
}
static void save_pub_pem(const RSA::PublicKey& k, const std::string& path) {
    ByteQueue q; k.DEREncodePublicKey(q);
    std::string der; StringSink s(der); q.CopyTo(s);
    write_file(path, der_to_pem(der, false));
}
static RSA::PrivateKey load_priv_pem(const std::string& path) {
    std::string der = pem_to_der(read_file(path), true);
    RSA::PrivateKey k;
    StringSource ss(der, true);
    k.BERDecodePrivateKey(ss, false, ss.MaxRetrievable());
    return k;
}
static RSA::PublicKey load_pub_pem(const std::string& path) {
    std::string der = pem_to_der(read_file(path), false);
    RSA::PublicKey k;
    StringSource ss(der, true);
    k.BERDecodePublicKey(ss, false, ss.MaxRetrievable());
    return k;
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers (single-level flat objects only — sufficient for envelope)
// ---------------------------------------------------------------------------
static std::string json_escape(const std::string& s) {
    std::string o; o.reserve(s.size() + 2);
    for (char c : s) {
        switch (c) {
            case '"' : o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default  : o += c;
        }
    }
    return o;
}

static std::string json_get_str(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    auto p = json.find(pat);
    if (p == std::string::npos)
        throw std::runtime_error("Envelope missing field: " + key);
    p = json.find(':', p);
    if (p == std::string::npos) throw std::runtime_error("Malformed envelope at: " + key);
    p = json.find('"', p);
    if (p == std::string::npos) throw std::runtime_error("Malformed envelope value: " + key);
    auto e = json.find('"', p + 1);
    if (e == std::string::npos) throw std::runtime_error("Unterminated string for: " + key);
    return json.substr(p + 1, e - p - 1);
}
static int json_get_int(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    auto p = json.find(pat);
    if (p == std::string::npos) throw std::runtime_error("Envelope missing field: " + key);
    p = json.find(':', p);
    auto q = p + 1;
    while (q < json.size() && (json[q] == ' ' || json[q] == '\t')) ++q;
    return std::stoi(json.substr(q));
}

// ---------------------------------------------------------------------------
// AES-256-GCM primitives
// ---------------------------------------------------------------------------
std::vector<std::uint8_t> aes_gcm_encrypt(const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& iv,
                                          const std::vector<std::uint8_t>& aad,
                                          const std::vector<std::uint8_t>& pt,
                                          std::vector<std::uint8_t>& tag_out)
{
    if (key.size() != 32) throw std::runtime_error("AES-256-GCM requires 32-byte key");
    if (iv.size() != 12)  throw std::runtime_error("AES-GCM requires 96-bit IV");

    GCM<AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string ct;
    AuthenticatedEncryptionFilter ef(enc, new StringSink(ct), false, 16);
    if (!aad.empty()) {
        ef.ChannelPut(AAD_CHANNEL, aad.data(), aad.size());
        ef.ChannelMessageEnd(AAD_CHANNEL);
    }
    ef.ChannelPut(DEFAULT_CHANNEL, pt.data(), pt.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    // EF appends 16-byte tag at the end of the default channel sink.
    if (ct.size() < 16) throw std::runtime_error("GCM internal: ciphertext too short");
    tag_out.assign(ct.end() - 16, ct.end());
    ct.resize(ct.size() - 16);
    return std::vector<std::uint8_t>(ct.begin(), ct.end());
}

std::vector<std::uint8_t> aes_gcm_decrypt(const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& iv,
                                          const std::vector<std::uint8_t>& aad,
                                          const std::vector<std::uint8_t>& ct,
                                          const std::vector<std::uint8_t>& tag)
{
    if (key.size() != 32) throw std::runtime_error("AES-256-GCM requires 32-byte key");
    if (iv.size() != 12)  throw std::runtime_error("AES-GCM requires 96-bit IV");
    if (tag.size() != 16) throw std::runtime_error("AES-GCM requires 16-byte tag");

    GCM<AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::string pt;
    AuthenticatedDecryptionFilter df(
        dec, new StringSink(pt),
        AuthenticatedDecryptionFilter::DEFAULT_FLAGS, 16);

    if (!aad.empty()) {
        df.ChannelPut(AAD_CHANNEL, aad.data(), aad.size());
        df.ChannelMessageEnd(AAD_CHANNEL);
    }
    df.ChannelPut(DEFAULT_CHANNEL, ct.data(), ct.size());
    df.ChannelPut(DEFAULT_CHANNEL, tag.data(), tag.size());
    df.ChannelMessageEnd(DEFAULT_CHANNEL);

    if (!df.GetLastResult())
        throw std::runtime_error("AES-GCM authentication failed");
    return std::vector<std::uint8_t>(pt.begin(), pt.end());
}

// ---------------------------------------------------------------------------
// RSA-OAEP wrappers.
//
// PK_EncryptorFilter in this Crypto++ build does not accept AlgorithmParameters,
// so we use the low-level Encryptor::Encrypt / Decryptor::Decrypt API directly.
// That is the only way to pass OAEP encoding parameters (the label).
// ---------------------------------------------------------------------------
static AlgorithmParameters make_oaep_params(const std::string& label) {
    if (label.empty()) return AlgorithmParameters();
    return MakeParameters(
        Name::EncodingParameters(),
        ConstByteArrayParameter(
            reinterpret_cast<const CryptoPP::byte*>(label.data()),
            label.size(),
            /*deepCopy=*/false));
}

static std::string oaep_encrypt(RandomNumberGenerator& rng,
                                const RSA::PublicKey& pub,
                                const std::string& pt,
                                const std::string& label)
{
    RSAES<OAEP<SHA256>>::Encryptor enc(pub);
    if (pt.size() > enc.FixedMaxPlaintextLength())
        throw std::runtime_error("Plaintext too long for OAEP");

    SecByteBlock ct(enc.CiphertextLength(pt.size()));
    AlgorithmParameters params = make_oaep_params(label);
    enc.Encrypt(rng,
                reinterpret_cast<const CryptoPP::byte*>(pt.data()), pt.size(),
                ct.BytePtr(),
                params);
    return std::string(reinterpret_cast<const char*>(ct.BytePtr()), ct.size());
}

static std::string oaep_decrypt(RandomNumberGenerator& rng,
                                const RSA::PrivateKey& priv,
                                const std::string& ct,
                                const std::string& label)
{
    RSAES<OAEP<SHA256>>::Decryptor dec(priv);
    if (ct.size() != dec.FixedCiphertextLength())
        throw std::runtime_error("OAEP ciphertext has wrong length");

    SecByteBlock buf(dec.MaxPlaintextLength(ct.size()));
    AlgorithmParameters params = make_oaep_params(label);
    DecodingResult r = dec.Decrypt(rng,
                                   reinterpret_cast<const CryptoPP::byte*>(ct.data()),
                                   ct.size(),
                                   buf.BytePtr(),
                                   params);
    if (!r.isValidCoding)
        throw std::runtime_error("OAEP decryption error (invalid padding or label)");
    return std::string(reinterpret_cast<const char*>(buf.BytePtr()), r.messageLength);
}

// ---------------------------------------------------------------------------
// Keygen
// ---------------------------------------------------------------------------
static std::string now_iso() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

KeyMeta keygen(int bits, const std::string& priv_pem_path, const std::string& pub_pem_path) {
    if (bits < 3072)
        throw std::runtime_error("Modulus size must be >= 3072 bits (NIST minimum)");

    AutoSeededRandomPool rng;
    RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, bits);
    RSA::PublicKey pub(priv);

    save_priv_pem(priv, priv_pem_path);
    save_pub_pem(pub,  pub_pem_path);

    KeyMeta m; m.modulus_bits = bits; m.hash = "SHA-256"; m.creation_time = now_iso();

    // Sidecar metadata
    std::ostringstream meta;
    meta << "{\n"
         << "  \"creation_time\": \"" << m.creation_time << "\",\n"
         << "  \"modulus_bits\": "    << m.modulus_bits   << ",\n"
         << "  \"hash\": \""          << m.hash           << "\"\n"
         << "}\n";
    write_file(priv_pem_path + ".meta.json", meta.str());
    return m;
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt with envelope JSON
// ---------------------------------------------------------------------------
void encrypt(const std::string& pub_pem_path,
             const std::string& in_path,
             const std::string& out_path,
             const std::string& label)
{
    AutoSeededRandomPool rng;
    RSA::PublicKey pub = load_pub_pem(pub_pem_path);

    int rsa_bits = (int)pub.GetModulus().BitCount();
    if (rsa_bits < 3072)
        throw std::runtime_error("Public key modulus < 3072 bits; refusing to encrypt");

    std::string pt = read_file(in_path);

    RSAES<OAEP<SHA256>>::Encryptor probe(pub);
    std::size_t max_pt = probe.FixedMaxPlaintextLength();

    std::ostringstream env;
    if (pt.size() <= max_pt) {
        // Pure RSA-OAEP
        std::string ct = oaep_encrypt(rng, pub, pt, label);
        env << "{\n"
            << "  \"mode\": \"RSA-OAEP\",\n"
            << "  \"rsa_modulus\": " << rsa_bits << ",\n"
            << "  \"hash\": \"SHA-256\",\n"
            << "  \"label\": \"" << json_escape(label) << "\",\n"
            << "  \"ciphertext\": \"" << b64_encode(ct) << "\"\n"
            << "}\n";
    } else {
        // Hybrid: AES-256-GCM with random 96-bit IV; wrap CEK via OAEP(label)
        SecByteBlock cek(32), iv(12);
        rng.GenerateBlock(cek, cek.size());
        rng.GenerateBlock(iv,  iv.size());

        std::string wrapped = oaep_encrypt(
            rng, pub,
            std::string(reinterpret_cast<const char*>(cek.data()), cek.size()),
            label);

        // Bind envelope metadata as AAD so tampering is detected.
        std::string aad_str = label;
        std::vector<std::uint8_t> tag;
        auto ct = aes_gcm_encrypt(
            std::vector<std::uint8_t>(cek.begin(), cek.end()),
            std::vector<std::uint8_t>(iv.begin(),  iv.end()),
            as_bytes(aad_str),
            as_bytes(pt),
            tag);

        env << "{\n"
            << "  \"mode\": \"RSA-OAEP-AES-GCM\",\n"
            << "  \"rsa_modulus\": " << rsa_bits << ",\n"
            << "  \"hash\": \"SHA-256\",\n"
            << "  \"label\": \"" << json_escape(label) << "\",\n"
            << "  \"wrapped_key\": \"" << b64_encode(wrapped) << "\",\n"
            << "  \"iv\": \""  << b64_encode(iv.data(), iv.size()) << "\",\n"
            << "  \"tag\": \"" << b64_encode(tag.data(), tag.size()) << "\",\n"
            << "  \"ciphertext\": \"" << b64_encode(ct.data(), ct.size()) << "\"\n"
            << "}\n";
    }
    write_file(out_path, env.str());
}

void decrypt(const std::string& priv_pem_path,
             const std::string& in_path,
             const std::string& out_path,
             const std::string& label)
{
    AutoSeededRandomPool rng;
    RSA::PrivateKey priv = load_priv_pem(priv_pem_path);

    std::string env = read_file(in_path);
    std::string mode = json_get_str(env, "mode");

    if (mode == "RSA-OAEP") {
        std::string env_label = json_get_str(env, "label");
        if (env_label != label)
            throw std::runtime_error("Label mismatch");
        std::string ct = b64_decode(json_get_str(env, "ciphertext"));
        std::string pt = oaep_decrypt(rng, priv, ct, label);
        write_file(out_path, pt);
    } else if (mode == "RSA-OAEP-AES-GCM") {
        std::string env_label = json_get_str(env, "label");
        if (env_label != label)
            throw std::runtime_error("Label mismatch");
        std::string wrapped = b64_decode(json_get_str(env, "wrapped_key"));
        std::string iv      = b64_decode(json_get_str(env, "iv"));
        std::string tag     = b64_decode(json_get_str(env, "tag"));
        std::string ct      = b64_decode(json_get_str(env, "ciphertext"));

        std::string cek_str = oaep_decrypt(rng, priv, wrapped, label);
        if (cek_str.size() != 32)
            throw std::runtime_error("Unwrapped CEK has wrong length");

        auto pt = aes_gcm_decrypt(
            as_bytes(cek_str), as_bytes(iv), as_bytes(label),
            as_bytes(ct), as_bytes(tag));
        write_file(out_path, as_string(pt));
    } else {
        throw std::runtime_error("Unknown envelope mode: " + mode);
    }
}

// ---------------------------------------------------------------------------
// Statistical benchmarking
// ---------------------------------------------------------------------------
static BenchStat stats(std::vector<double>& per_op, int n, int block_size) {
    BenchStat s; s.n = n; s.block_size = block_size;
    if (per_op.empty()) return s;
    std::sort(per_op.begin(), per_op.end());
    s.samples_ms = per_op;  // already sorted; mirrors the median used below
    s.median_ms = per_op[per_op.size() / 2];
    double sum = std::accumulate(per_op.begin(), per_op.end(), 0.0);
    s.mean_ms = sum / per_op.size();
    double sq = 0;
    for (double x : per_op) sq += (x - s.mean_ms) * (x - s.mean_ms);
    s.stddev_ms = std::sqrt(sq / std::max<std::size_t>(1, per_op.size() - 1));
    double se = s.stddev_ms / std::sqrt((double)per_op.size());
    s.ci95_low  = s.mean_ms - 1.96 * se;
    s.ci95_high = s.mean_ms + 1.96 * se;
    return s;
}

// Runs `fn` for `block_size` ops per timed block, repeats `n` blocks after
// a 1-second warm-up. Reports PER-OPERATION latency (block_time / block_size).
template <typename F>
static BenchStat run_bench(int n, int block_size, F&& fn) {
    if (n < 1) n = 1;
    if (block_size < 1) block_size = 1;

    // Warm-up: at least 1 s, capped to avoid stalling slow ops.
    auto wstart = std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now() - wstart < std::chrono::seconds(1)) {
        fn();
    }

    std::vector<double> per_op;
    per_op.reserve(n);
    for (int i = 0; i < n; ++i) {
        auto t0 = std::chrono::steady_clock::now();
        for (int k = 0; k < block_size; ++k) fn();
        auto t1 = std::chrono::steady_clock::now();
        double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        per_op.push_back(ms / block_size);
    }
    return stats(per_op, n, block_size);
}

BenchStat bench_keygen(int bits, int n, int block_size) {
    AutoSeededRandomPool rng;
    return run_bench(n, block_size, [&]{
        RSA::PrivateKey k;
        k.GenerateRandomWithKeySize(rng, bits);
    });
}

BenchStat bench_oaep_enc(int bits, int n, int block_size) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, bits);
    RSA::PublicKey pub(priv);
    std::string msg(32, 'A');
    return run_bench(n, block_size, [&]{ (void)oaep_encrypt(rng, pub, msg, ""); });
}

BenchStat bench_oaep_dec(int bits, int n, int block_size) {
    AutoSeededRandomPool rng;
    RSA::PrivateKey priv;
    priv.GenerateRandomWithKeySize(rng, bits);
    RSA::PublicKey pub(priv);
    std::string msg(32, 'A');
    std::string ct = oaep_encrypt(rng, pub, msg, "");
    return run_bench(n, block_size, [&]{ (void)oaep_decrypt(rng, priv, ct, ""); });
}

BenchStat bench_aes_gcm(int n, std::size_t msg_size, int block_size) {
    AutoSeededRandomPool rng;
    std::vector<std::uint8_t> key(32), iv(12), pt(msg_size, 0x42);
    rng.GenerateBlock(key.data(), key.size());
    rng.GenerateBlock(iv.data(),  iv.size());
    return run_bench(n, block_size, [&]{
        std::vector<std::uint8_t> tag;
        (void)aes_gcm_encrypt(key, iv, {}, pt, tag);
    });
}

BenchStat bench_aes_gcm_dec(int n, std::size_t msg_size, int block_size) {
    AutoSeededRandomPool rng;
    std::vector<std::uint8_t> key(32), iv(12), pt(msg_size, 0x42);
    rng.GenerateBlock(key.data(), key.size());
    rng.GenerateBlock(iv.data(),  iv.size());
    std::vector<std::uint8_t> tag;
    auto ct = aes_gcm_encrypt(key, iv, {}, pt, tag);  // build a valid ct+tag once
    return run_bench(n, block_size, [&]{
        (void)aes_gcm_decrypt(key, iv, {}, ct, tag);
    });
}

// ---------------------------------------------------------------------------
// KAT runner 
// ---------------------------------------------------------------------------
static std::vector<std::uint8_t> hex_decode(const std::string& h) {
    std::string out;
    StringSource(h, true, new HexDecoder(new StringSink(out)));
    return std::vector<std::uint8_t>(out.begin(), out.end());
}
static std::string hex_encode(const std::vector<std::uint8_t>& b) {
    std::string out;
    StringSource(std::string(b.begin(), b.end()), true,
                 new HexEncoder(new StringSink(out), false));
    return out;
}

// Very small object iterator: find every "{...}" inside top-level "tests": [ ... ]
static std::vector<std::string> split_tests(const std::string& json) {
    auto a = json.find("\"tests\"");
    if (a == std::string::npos) throw std::runtime_error("KAT: missing 'tests' array");
    a = json.find('[', a);
    if (a == std::string::npos) throw std::runtime_error("KAT: malformed 'tests' array");
    std::vector<std::string> out;
    int depth = 0; std::size_t start = 0;
    for (std::size_t i = a + 1; i < json.size(); ++i) {
        char c = json[i];
        if (c == '{') { if (depth == 0) start = i; ++depth; }
        else if (c == '}') {
            --depth;
            if (depth == 0) out.push_back(json.substr(start, i - start + 1));
        } else if (c == ']' && depth == 0) break;
    }
    return out;
}

std::pair<int,int> run_kat(const std::string& kat_json_path) {
    std::string blob = read_file(kat_json_path);
    auto cases = split_tests(blob);
    int pass = 0, fail = 0;

    for (auto& tc : cases) {
        std::string name = json_get_str(tc, "name");
        std::string type = json_get_str(tc, "type");
        bool ok = false;
        std::string why;
        try {
            if (type == "aes_gcm_encrypt") {
                auto key = hex_decode(json_get_str(tc, "key_hex"));
                auto iv  = hex_decode(json_get_str(tc, "iv_hex"));
                auto aad = hex_decode(json_get_str(tc, "aad_hex"));
                auto pt  = hex_decode(json_get_str(tc, "pt_hex"));
                auto ect = json_get_str(tc, "expected_ct_hex");
                auto etg = json_get_str(tc, "expected_tag_hex");
                std::vector<std::uint8_t> tag;
                auto ct = aes_gcm_encrypt(key, iv, aad, pt, tag);
                ok = (hex_encode(ct) == ect) && (hex_encode(tag) == etg);
                if (!ok) why = "ct/tag mismatch";
            } else if (type == "aes_gcm_decrypt") {
                auto key = hex_decode(json_get_str(tc, "key_hex"));
                auto iv  = hex_decode(json_get_str(tc, "iv_hex"));
                auto aad = hex_decode(json_get_str(tc, "aad_hex"));
                auto ct  = hex_decode(json_get_str(tc, "ct_hex"));
                auto tag = hex_decode(json_get_str(tc, "tag_hex"));
                auto ept = json_get_str(tc, "expected_pt_hex");
                auto pt  = aes_gcm_decrypt(key, iv, aad, ct, tag);
                ok = (hex_encode(pt) == ept);
                if (!ok) why = "pt mismatch";
            } else if (type == "aes_gcm_roundtrip") {
                // Positive: encrypt then decrypt with the same key/iv → plaintext matches.
                AutoSeededRandomPool rng;
                auto pt  = hex_decode(json_get_str(tc, "pt_hex"));
                std::vector<std::uint8_t> key(32), iv(12), aad{};
                rng.GenerateBlock(key.data(), key.size());
                rng.GenerateBlock(iv.data(),  iv.size());
                std::vector<std::uint8_t> tag;
                auto ct = aes_gcm_encrypt(key, iv, aad, pt, tag);
                auto back = aes_gcm_decrypt(key, iv, aad, ct, tag);
                ok = (back == pt);
                if (!ok) why = "GCM roundtrip mismatch";
            } else if (type == "aes_gcm_tamper_roundtrip") {
                // Negative: encrypt → flip a byte → decrypt must fail authentication.
                AutoSeededRandomPool rng;
                auto pt = hex_decode(json_get_str(tc, "pt_hex"));
                std::string target = json_get_str(tc, "tamper");  // "ct" or "tag"
                std::vector<std::uint8_t> key(32), iv(12), aad{};
                rng.GenerateBlock(key.data(), key.size());
                rng.GenerateBlock(iv.data(),  iv.size());
                std::vector<std::uint8_t> tag;
                auto ct = aes_gcm_encrypt(key, iv, aad, pt, tag);
                if (target == "ct") ct[ct.size() / 2] ^= 0x01;
                else                tag[0] ^= 0x01;
                bool failed = false;
                try { (void)aes_gcm_decrypt(key, iv, aad, ct, tag); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected GCM auth failure after tampering " + target;
            } else if (type == "aes_gcm_decrypt_fail") {
                // Expects authentication failure.
                auto key = hex_decode(json_get_str(tc, "key_hex"));
                auto iv  = hex_decode(json_get_str(tc, "iv_hex"));
                auto aad = hex_decode(json_get_str(tc, "aad_hex"));
                auto ct  = hex_decode(json_get_str(tc, "ct_hex"));
                auto tag = hex_decode(json_get_str(tc, "tag_hex"));
                bool failed = false;
                try { aes_gcm_decrypt(key, iv, aad, ct, tag); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected GCM auth failure but it succeeded";
            } else if (type == "rsa_oaep_roundtrip") {
                int bits = json_get_int(tc, "bits");
                auto pt  = hex_decode(json_get_str(tc, "pt_hex"));
                std::string label = json_get_str(tc, "label");
                AutoSeededRandomPool rng;
                RSA::PrivateKey priv;
                priv.GenerateRandomWithKeySize(rng, bits);
                RSA::PublicKey pub(priv);
                std::string ct = oaep_encrypt(rng, pub, std::string(pt.begin(), pt.end()), label);
                std::string back = oaep_decrypt(rng, priv, ct, label);
                ok = (back == std::string(pt.begin(), pt.end()));
                if (!ok) why = "OAEP roundtrip mismatch";
            } else if (type == "rsa_oaep_wrong_label") {
                int bits = json_get_int(tc, "bits");
                auto pt  = hex_decode(json_get_str(tc, "pt_hex"));
                AutoSeededRandomPool rng;
                RSA::PrivateKey priv;
                priv.GenerateRandomWithKeySize(rng, bits);
                RSA::PublicKey pub(priv);
                std::string ct = oaep_encrypt(rng, pub, std::string(pt.begin(), pt.end()), "labelA");
                bool failed = false;
                try { (void)oaep_decrypt(rng, priv, ct, "labelB"); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected OAEP failure on wrong label";
            } else if (type == "rsa_oaep_altered_ct") {
                // Lab 3 §4: "Altered RSA ciphertext -> decryption fails".
                int bits = json_get_int(tc, "bits");
                auto pt  = hex_decode(json_get_str(tc, "pt_hex"));
                AutoSeededRandomPool rng;
                RSA::PrivateKey priv;
                priv.GenerateRandomWithKeySize(rng, bits);
                RSA::PublicKey pub(priv);
                std::string ct = oaep_encrypt(rng, pub, std::string(pt.begin(), pt.end()), "");
                // Flip a byte in the middle of the ciphertext.
                ct[ct.size() / 2] ^= 0x01;
                bool failed = false;
                try { (void)oaep_decrypt(rng, priv, ct, ""); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected OAEP decryption to fail on altered ciphertext";
            } else if (type == "rsa_oaep_wrong_key") {
                // Lab 3 §4: "Wrong private key -> failure".
                int bits = json_get_int(tc, "bits");
                auto pt  = hex_decode(json_get_str(tc, "pt_hex"));
                AutoSeededRandomPool rng;
                RSA::PrivateKey privA, privB;
                privA.GenerateRandomWithKeySize(rng, bits);
                privB.GenerateRandomWithKeySize(rng, bits);
                RSA::PublicKey pubA(privA);
                std::string ct = oaep_encrypt(rng, pubA, std::string(pt.begin(), pt.end()), "");
                bool failed = false;
                try { (void)oaep_decrypt(rng, privB, ct, ""); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected OAEP failure when decrypting with wrong private key";
            } else if (type == "envelope_malformed") {
                // Lab 3 common: "Fail closed on parsing errors / malformed input".
                // Writes a broken envelope to a temp file and expects decrypt to throw.
                std::string broken = json_get_str(tc, "envelope_text");
                // We test the parser via decrypt(): create a temp key pair, write
                // the broken envelope, call decrypt, and verify it fails.
                AutoSeededRandomPool rng;
                RSA::PrivateKey priv;
                priv.GenerateRandomWithKeySize(rng, 3072);
                RSA::PublicKey pub(priv);
                std::string priv_path = "_kat_tmp_priv.pem";
                std::string env_path  = "_kat_tmp_env.json";
                save_priv_pem(priv, priv_path);
                write_file(env_path, broken);
                bool failed = false;
                try { decrypt(priv_path, env_path, "_kat_tmp_out.bin", ""); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected fail-closed on malformed envelope";
            } else if (type == "rsa_modulus_too_small") {
                // Lab 3: modulus must be >= 3072. keygen() must reject smaller.
                int bits = json_get_int(tc, "bits");
                bool failed = false;
                try { (void)keygen(bits, "_kat_tmp_priv.pem", "_kat_tmp_pub.pem"); }
                catch (...) { failed = true; }
                ok = failed;
                if (!ok) why = "expected keygen to refuse bits < 3072";
            } else {
                why = "unknown test type: " + type;
            }
        } catch (const std::exception& e) {
            why = e.what();
        }
        if (ok) { ++pass; std::cout << "  PASS  " << name << "\n"; }
        else    { ++fail; std::cout << "  FAIL  " << name << "  (" << why << ")\n"; }
    }
    std::cout << "\nSummary: " << pass << " passed, " << fail << " failed, "
              << (pass + fail) << " total.\n";
    return {pass, fail};
}

} // namespace rsa_lab
