#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace rsa_lab {

struct KeyMeta {
    int    modulus_bits = 0;
    std::string hash;
    std::string creation_time;
};

struct BenchStat {
    int    n = 0;             // number of samples (blocks)
    int    block_size = 1;    // operations per block
    double mean_ms = 0, median_ms = 0, stddev_ms = 0;  // PER-OPERATION time
    double ci95_low = 0, ci95_high = 0;
    // Raw per-operation timings (sorted), one entry per block. Lets callers
    // emit audit logs / CSV for reports.
    std::vector<double> samples_ms;
};

// Throws std::runtime_error on failure.
KeyMeta keygen(int bits,
               const std::string& priv_pem_path,
               const std::string& pub_pem_path);

// Auto-switches between pure RSA-OAEP and hybrid RSA-OAEP + AES-256-GCM.
// Output is a JSON envelope (UTF-8 text). label is optional OAEP label.
void encrypt(const std::string& pub_pem_path,
             const std::string& in_path,
             const std::string& out_path,
             const std::string& label = "");

// Parses envelope JSON, verifies integrity, writes plaintext.
// label must match the value used during encryption.
void decrypt(const std::string& priv_pem_path,
             const std::string& in_path,
             const std::string& out_path,
             const std::string& label = "");

// Returns {passed, failed}. Prints PASS/FAIL per test.
std::pair<int,int> run_kat(const std::string& kat_json_path);

// Statistical benchmarks. Spec (Common Reqs §4): 1 s warm-up, block of
// ~1000 ops, repeat 30..100 times, report mean/median/sd/95%CI.
//   n          = number of timed blocks (samples). Spec: 30..100.
//   block_size = operations per block. Spec: ~1000.
// Reported latency is PER OPERATION (block time / block_size).
// Defaults follow the spec literally; total runtime for RSA-keygen at the
// default settings can be several hours and that is acceptable per spec.
BenchStat bench_keygen   (int bits, int n, int block_size = 1000);
BenchStat bench_oaep_enc (int bits, int n, int block_size = 1000);
BenchStat bench_oaep_dec (int bits, int n, int block_size = 1000);
BenchStat bench_aes_gcm     (int n, std::size_t msg_size, int block_size = 1000);
BenchStat bench_aes_gcm_dec (int n, std::size_t msg_size, int block_size = 1000);

// Low-level primitives reused by KAT runner + tests.
std::vector<std::uint8_t> aes_gcm_encrypt(const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& iv,
                                          const std::vector<std::uint8_t>& aad,
                                          const std::vector<std::uint8_t>& pt,
                                          std::vector<std::uint8_t>& tag_out);

std::vector<std::uint8_t> aes_gcm_decrypt(const std::vector<std::uint8_t>& key,
                                          const std::vector<std::uint8_t>& iv,
                                          const std::vector<std::uint8_t>& aad,
                                          const std::vector<std::uint8_t>& ct,
                                          const std::vector<std::uint8_t>& tag);

} // namespace rsa_lab
