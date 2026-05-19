// RSA_LAB_BUILD_DLL is set by CMake (target_compile_definitions).
#include "c_api.h"
#include "rsa_core.h"

#include <string>
#include <mutex>
#include <exception>

namespace {
    std::mutex g_err_mu;
    std::string g_err;
    void set_err(const std::string& s) {
        std::lock_guard<std::mutex> lk(g_err_mu);
        g_err = s;
    }
}

extern "C" {

const char* rsa_last_error(void) {
    std::lock_guard<std::mutex> lk(g_err_mu);
    return g_err.c_str();
}

#define GUARD_BEGIN try {
#define GUARD_END(ret) } catch (const std::exception& e) { set_err(e.what()); return (ret); } \
                        catch (...) { set_err("unknown error"); return (ret); }

int rsa_keygen(int bits, const char* priv, const char* pub) {
    GUARD_BEGIN
    rsa_lab::keygen(bits, priv ? priv : "", pub ? pub : "");
    set_err("");
    return 0;
    GUARD_END(1)
}

int rsa_encrypt(const char* pub, const char* in_, const char* out_, const char* label) {
    GUARD_BEGIN
    rsa_lab::encrypt(pub ? pub : "", in_ ? in_ : "", out_ ? out_ : "",
                     label ? label : "");
    set_err("");
    return 0;
    GUARD_END(1)
}

int rsa_decrypt(const char* priv, const char* in_, const char* out_, const char* label) {
    GUARD_BEGIN
    rsa_lab::decrypt(priv ? priv : "", in_ ? in_ : "", out_ ? out_ : "",
                     label ? label : "");
    set_err("");
    return 0;
    GUARD_END(1)
}

int rsa_run_kat(const char* path, int* passed, int* failed) {
    GUARD_BEGIN
    auto r = rsa_lab::run_kat(path ? path : "");
    if (passed) *passed = r.first;
    if (failed) *failed = r.second;
    set_err("");
    return r.second == 0 ? 0 : 1;
    GUARD_END(1)
}

static void fill(const rsa_lab::BenchStat& s,
                 double* mean, double* median, double* stddev,
                 double* ci_lo, double* ci_hi) {
    if (mean)   *mean   = s.mean_ms;
    if (median) *median = s.median_ms;
    if (stddev) *stddev = s.stddev_ms;
    if (ci_lo)  *ci_lo  = s.ci95_low;
    if (ci_hi)  *ci_hi  = s.ci95_high;
}

int rsa_bench_keygen(int bits, int n, double* m, double* md, double* sd, double* lo, double* hi) {
    GUARD_BEGIN
    fill(rsa_lab::bench_keygen(bits, n /* block_size = 1 */), m, md, sd, lo, hi);
    set_err(""); return 0;
    GUARD_END(1)
}
int rsa_bench_oaep_enc(int bits, int n, double* m, double* md, double* sd, double* lo, double* hi) {
    GUARD_BEGIN
    fill(rsa_lab::bench_oaep_enc(bits, n /* block_size = 100 */), m, md, sd, lo, hi);
    set_err(""); return 0;
    GUARD_END(1)
}
int rsa_bench_oaep_dec(int bits, int n, double* m, double* md, double* sd, double* lo, double* hi) {
    GUARD_BEGIN
    fill(rsa_lab::bench_oaep_dec(bits, n /* block_size = 100 */), m, md, sd, lo, hi);
    set_err(""); return 0;
    GUARD_END(1)
}
int rsa_bench_aes_gcm(int n, unsigned long long size,
                      double* m, double* md, double* sd, double* lo, double* hi) {
    GUARD_BEGIN
    fill(rsa_lab::bench_aes_gcm(n, (std::size_t)size /* block_size = 1000 */),
         m, md, sd, lo, hi);
    set_err(""); return 0;
    GUARD_END(1)
}

} // extern "C"
