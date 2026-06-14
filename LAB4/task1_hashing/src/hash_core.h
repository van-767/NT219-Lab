// Lab 4 Task 1 - Hashing core (SHA-2, SHA-3, SHAKE) through Crypto++.
// Shared by CLI and DLL export.
#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace hashlab {

using Bytes = std::vector<uint8_t>;

enum class Algo {
    SHA224, SHA256, SHA384, SHA512,
    SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    SHAKE128, SHAKE256
};

Algo        algo_from_string(const std::string& s);
const char* algo_to_string(Algo a);
bool        algo_is_xof(Algo a);            // true cho SHAKE128/256
size_t      algo_fixed_outlen(Algo a);      // 0 for XOF

// Hash buffer / file. XOF algorithms require out_len > 0.
Bytes hash_bytes(Algo a, const Bytes& msg, size_t xof_len = 0);
Bytes hash_file (Algo a, const std::string& path, size_t xof_len = 0);

// Streamed file hashing for large files. Reads 64 KiB chunks.
Bytes hash_file_streamed(Algo a, const std::string& path, size_t xof_len = 0);

// Helpers
Bytes       read_file(const std::string& path);
void        write_file(const std::string& path, const Bytes& b);
void        write_file(const std::string& path, const std::string& s);
std::string hex_encode(const Bytes& b);
Bytes       hex_decode(const std::string& s);

} // namespace hashlab
