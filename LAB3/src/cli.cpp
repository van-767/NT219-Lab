#include "rsa_core.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>
#include <cstring>
#include <iomanip>
#include <cstdlib>

static void usage() {
    std::cout <<
"rsatool — RSA-OAEP + Hybrid (AES-256-GCM) [Lab 3]\n"
"\n"
"Commands:\n"
"  keygen   --bits N --priv FILE --pub FILE           (N >= 3072)\n"
"  encrypt  --pub FILE --in FILE --out FILE [--label STR]\n"
"  decrypt  --priv FILE --in FILE --out FILE [--label STR]\n"
"  kat      --kat FILE\n"
"  bench    --op {keygen|enc|dec|gcm_enc|gcm_dec} --bits N --n N [--block N] [--size BYTES]\n"
"           [--log FILE]\n"
"           (spec: 1s warm-up; n = blocks (30..100); block = ops/block (~1000).\n"
"            Defaults n=30, block=1000. RSA-3072 keygen at defaults can take\n"
"            hours — that is expected per the lab protocol.\n"
"            --log writes a CSV: header lines '# key,value' then 'sample_idx,per_op_ms'.)\n"
"\n"
"Notes:\n"
"  - Encrypt auto-switches to AES-256-GCM hybrid when plaintext exceeds the\n"
"    RSA-OAEP limit (k - 2*hLen - 2).\n"
"  - Label is the OAEP encoding parameter AND bound as GCM AAD; wrong label\n"
"    must cause decryption to fail.\n";
}

static const char* arg(int argc, char** argv, const char* key, const char* def = nullptr) {
    for (int i = 0; i + 1 < argc; ++i)
        if (std::strcmp(argv[i], key) == 0) return argv[i + 1];
    return def;
}

static void print_stat(const char* label, const rsa_lab::BenchStat& s) {
    std::cout << std::fixed << std::setprecision(4);
    std::cout << label
              << ": n=" << s.n << " blocks x " << s.block_size << " ops"
              << "  per-op mean="   << s.mean_ms   << " ms"
              << "  median=" << s.median_ms << " ms"
              << "  sd="     << s.stddev_ms << " ms"
              << "  95%CI=[" << s.ci95_low << ", " << s.ci95_high << "] ms\n";
}

static std::string iso_now() {
    auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

static void write_log(const std::string& path,
                      const std::string& op, int bits,
                      unsigned long long size,
                      const rsa_lab::BenchStat& s)
{
    std::ofstream f(path, std::ios::binary);
    if (!f) { std::cerr << "WARN: cannot open log: " << path << "\n"; return; }
    f << std::fixed << std::setprecision(6);
    f << "# timestamp_utc," << iso_now() << "\n"
      << "# op,"            << op << "\n"
      << "# rsa_bits,"      << bits << "\n"
      << "# aes_msg_size,"  << size << "\n"
      << "# n_blocks,"      << s.n << "\n"
      << "# block_size,"    << s.block_size << "\n"
      << "# total_ops,"     << (long long)s.n * s.block_size << "\n"
      << "# per_op_mean_ms,"   << s.mean_ms   << "\n"
      << "# per_op_median_ms," << s.median_ms << "\n"
      << "# per_op_stddev_ms," << s.stddev_ms << "\n"
      << "# per_op_ci95_low_ms,"  << s.ci95_low  << "\n"
      << "# per_op_ci95_high_ms," << s.ci95_high << "\n"
      << "sample_idx,per_op_ms\n";
    for (std::size_t i = 0; i < s.samples_ms.size(); ++i)
        f << i << "," << s.samples_ms[i] << "\n";
    std::cout << "log written: " << path << "  ("
              << s.samples_ms.size() << " samples)\n";
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];
    try {
        if (cmd == "keygen") {
            int bits = std::atoi(arg(argc, argv, "--bits", "3072"));
            auto m = rsa_lab::keygen(bits,
                arg(argc, argv, "--priv", "priv.pem"),
                arg(argc, argv, "--pub",  "pub.pem"));
            std::cout << "OK keygen " << m.modulus_bits << "-bit  " << m.creation_time << "\n";
        } else if (cmd == "encrypt") {
            rsa_lab::encrypt(
                arg(argc, argv, "--pub", ""),
                arg(argc, argv, "--in",  ""),
                arg(argc, argv, "--out", ""),
                arg(argc, argv, "--label", ""));
            std::cout << "OK encrypt\n";
        } else if (cmd == "decrypt") {
            rsa_lab::decrypt(
                arg(argc, argv, "--priv", ""),
                arg(argc, argv, "--in",   ""),
                arg(argc, argv, "--out",  ""),
                arg(argc, argv, "--label", ""));
            std::cout << "OK decrypt\n";
        } else if (cmd == "kat") {
            auto r = rsa_lab::run_kat(arg(argc, argv, "--kat", ""));
            return r.second == 0 ? 0 : 2;
        } else if (cmd == "bench") {
            std::string op   = arg(argc, argv, "--op", "");
            int bits  = std::atoi(arg(argc, argv, "--bits",  "3072"));
            int n     = std::atoi(arg(argc, argv, "--n",     "30"));
            int blk = std::atoi(arg(argc, argv, "--block", "1000"));
            unsigned long long size =
                std::strtoull(arg(argc, argv, "--size", "1024"), nullptr, 10);
            const char* log = arg(argc, argv, "--log", nullptr);
            rsa_lab::BenchStat s;
            std::string label;
            if      (op == "keygen")  { s = rsa_lab::bench_keygen(bits, n, blk);                 label = "keygen"; }
            else if (op == "enc")     { s = rsa_lab::bench_oaep_enc(bits, n, blk);               label = "oaep_enc"; }
            else if (op == "dec")     { s = rsa_lab::bench_oaep_dec(bits, n, blk);               label = "oaep_dec"; }
            else if (op == "gcm" || op == "gcm_enc")
                                      { s = rsa_lab::bench_aes_gcm(n, (std::size_t)size, blk);   label = "aes_gcm_enc"; }
            else if (op == "gcm_dec") { s = rsa_lab::bench_aes_gcm_dec(n, (std::size_t)size, blk); label = "aes_gcm_dec"; }
            else { std::cerr << "Unknown --op\n"; return 1; }
            print_stat(label.c_str(), s);
            if (log) write_log(log, label, bits, size, s);
        } else {
            usage();
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 2;
    }
    return 0;
}
