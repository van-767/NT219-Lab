#include "hash_core.h"

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

#include <fstream>
#include <sstream>
#include <stdexcept>

using namespace CryptoPP;
namespace hashlab {

Algo algo_from_string(const std::string& s) {
    if (s == "sha224"   || s == "SHA-224")    return Algo::SHA224;
    if (s == "sha256"   || s == "SHA-256")    return Algo::SHA256;
    if (s == "sha384"   || s == "SHA-384")    return Algo::SHA384;
    if (s == "sha512"   || s == "SHA-512")    return Algo::SHA512;
    if (s == "sha3-224" || s == "SHA3-224")   return Algo::SHA3_224;
    if (s == "sha3-256" || s == "SHA3-256")   return Algo::SHA3_256;
    if (s == "sha3-384" || s == "SHA3-384")   return Algo::SHA3_384;
    if (s == "sha3-512" || s == "SHA3-512")   return Algo::SHA3_512;
    if (s == "shake128" || s == "SHAKE128")   return Algo::SHAKE128;
    if (s == "shake256" || s == "SHAKE256")   return Algo::SHAKE256;
    throw std::runtime_error("Unknown algo: " + s);
}

const char* algo_to_string(Algo a) {
    switch (a) {
        case Algo::SHA224:   return "SHA-224";
        case Algo::SHA256:   return "SHA-256";
        case Algo::SHA384:   return "SHA-384";
        case Algo::SHA512:   return "SHA-512";
        case Algo::SHA3_224: return "SHA3-224";
        case Algo::SHA3_256: return "SHA3-256";
        case Algo::SHA3_384: return "SHA3-384";
        case Algo::SHA3_512: return "SHA3-512";
        case Algo::SHAKE128: return "SHAKE128";
        case Algo::SHAKE256: return "SHAKE256";
    }
    return "?";
}

bool   algo_is_xof(Algo a) { return a == Algo::SHAKE128 || a == Algo::SHAKE256; }
size_t algo_fixed_outlen(Algo a) {
    switch (a) {
        case Algo::SHA224: case Algo::SHA3_224: return 28;
        case Algo::SHA256: case Algo::SHA3_256: return 32;
        case Algo::SHA384: case Algo::SHA3_384: return 48;
        case Algo::SHA512: case Algo::SHA3_512: return 64;
        default: return 0;
    }
}

// Tạo hash transformation tương ứng với algo. Caller phải free.
static HashTransformation* make_hash(Algo a, size_t xof_len = 0) {
    switch (a) {
        case Algo::SHA224:   return new SHA224();
        case Algo::SHA256:   return new SHA256();
        case Algo::SHA384:   return new SHA384();
        case Algo::SHA512:   return new SHA512();
        case Algo::SHA3_224: return new SHA3_224();
        case Algo::SHA3_256: return new SHA3_256();
        case Algo::SHA3_384: return new SHA3_384();
        case Algo::SHA3_512: return new SHA3_512();
        case Algo::SHAKE128:
            if (xof_len == 0) throw std::runtime_error("SHAKE128 cần --outlen > 0");
            return new SHAKE128(xof_len);
        case Algo::SHAKE256:
            if (xof_len == 0) throw std::runtime_error("SHAKE256 cần --outlen > 0");
            return new SHAKE256(xof_len);
    }
    throw std::runtime_error("Unknown algo");
}

Bytes hash_bytes(Algo a, const Bytes& msg, size_t xof_len) {
    std::unique_ptr<HashTransformation> h(make_hash(a, xof_len));
    size_t out = algo_is_xof(a) ? xof_len : algo_fixed_outlen(a);
    Bytes digest(out);
    h->CalculateDigest(digest.data(), msg.data(), msg.size());
    return digest;
}

Bytes hash_file(Algo a, const std::string& path, size_t xof_len) {
    return hash_file_streamed(a, path, xof_len);
}

Bytes hash_file_streamed(Algo a, const std::string& path, size_t xof_len) {
    std::unique_ptr<HashTransformation> h(make_hash(a, xof_len));

    std::ifstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot open: " + path);

    constexpr size_t BUF = 64 * 1024;
    std::vector<char> buf(BUF);
    while (f.read(buf.data(), BUF)) {
        h->Update(reinterpret_cast<const CryptoPP::byte*>(buf.data()), BUF);
    }
    if (f.gcount() > 0)
        h->Update(reinterpret_cast<const CryptoPP::byte*>(buf.data()),
                  static_cast<size_t>(f.gcount()));

    size_t out = algo_is_xof(a) ? xof_len : algo_fixed_outlen(a);
    Bytes digest(out);
    h->Final(digest.data());
    return digest;
}

// ──── Helpers ────────────────────────────────────────────────────────
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

} // namespace hashlab
