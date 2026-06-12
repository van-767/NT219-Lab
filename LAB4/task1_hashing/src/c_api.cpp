// HASH_LAB_BUILD_DLL được CMake set qua target_compile_definitions.
#include "c_api.h"
#include "hash_core.h"

#include <chrono>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <string>

namespace {
std::mutex g_err_mu;
std::string g_err;
void set_err(const std::string& s) { std::lock_guard<std::mutex> lk(g_err_mu); g_err = s; }

void copy_hex(const std::string& hex, char* out, int cap) {
    if (cap <= 0) return;
    int n = std::min<int>((int)hex.size(), cap - 1);
    std::memcpy(out, hex.data(), n);
    out[n] = '\0';
}

std::string json_get_str(const std::string& j, const std::string& key) {
    auto p = j.find("\"" + key + "\"");
    if (p == std::string::npos) throw std::runtime_error("missing field: " + key);
    p = j.find(':', p); p = j.find('"', p);
    auto e = j.find('"', p + 1);
    return j.substr(p + 1, e - p - 1);
}
int json_get_int(const std::string& j, const std::string& key, int def) {
    auto p = j.find("\"" + key + "\"");
    if (p == std::string::npos) return def;
    p = j.find(':', p);
    auto q = p + 1; while (q < j.size() && (j[q] == ' ' || j[q] == '\t')) ++q;
    try { return std::stoi(j.substr(q)); } catch (...) { return def; }
}
std::vector<std::string> split_tests(const std::string& json) {
    auto a = json.find("\"tests\"");
    if (a == std::string::npos) throw std::runtime_error("no 'tests' array");
    a = json.find('[', a);
    std::vector<std::string> out;
    int depth = 0; std::size_t start = 0;
    for (std::size_t i = a + 1; i < json.size(); ++i) {
        char c = json[i];
        if (c == '{') { if (depth == 0) start = i; ++depth; }
        else if (c == '}') { --depth; if (depth == 0) out.push_back(json.substr(start, i - start + 1)); }
        else if (c == ']' && depth == 0) break;
    }
    return out;
}
} // anon

#define GUARD_BEGIN try {
#define GUARD_END(ret) } catch (const std::exception& e) { set_err(e.what()); return (ret); } \
                        catch (...) { set_err("unknown error"); return (ret); }

extern "C" {

const char* hash_last_error(void) {
    std::lock_guard<std::mutex> lk(g_err_mu);
    return g_err.c_str();
}

int hash_text(const char* algo, const char* text, int text_len,
              int outlen, char* out_hex, int out_hex_size) {
    GUARD_BEGIN
    auto a = hashlab::algo_from_string(algo ? algo : "");
    hashlab::Bytes msg(text, text + (text_len < 0 ? (int)std::strlen(text ? text : "") : text_len));
    auto d = hashlab::hash_bytes(a, msg, (size_t)outlen);
    copy_hex(hashlab::hex_encode(d), out_hex, out_hex_size);
    set_err(""); return 0;
    GUARD_END(1)
}

int hash_file(const char* algo, const char* file_path,
              int outlen, char* out_hex, int out_hex_size) {
    GUARD_BEGIN
    auto a = hashlab::algo_from_string(algo ? algo : "");
    auto d = hashlab::hash_file_streamed(a, file_path ? file_path : "", (size_t)outlen);
    copy_hex(hashlab::hex_encode(d), out_hex, out_hex_size);
    set_err(""); return 0;
    GUARD_END(1)
}

int hash_run_kat(const char* json_path, int* out_passed, int* out_failed) {
    GUARD_BEGIN
    auto bytes = hashlab::read_file(json_path ? json_path : "");
    std::string json(bytes.begin(), bytes.end());
    auto cases = split_tests(json);
    int pass = 0, fail = 0;
    for (auto& tc : cases) {
        try {
            auto a = hashlab::algo_from_string(json_get_str(tc, "algo"));
            auto msg = hashlab::hex_decode(json_get_str(tc, "msg_hex"));
            int outlen = json_get_int(tc, "outlen", 0);
            auto got = hashlab::hash_bytes(a, msg, (size_t)outlen);
            std::string g = hashlab::hex_encode(got);
            std::string e = json_get_str(tc, "expected_hex");
            std::transform(g.begin(), g.end(), g.begin(), ::tolower);
            std::transform(e.begin(), e.end(), e.begin(), ::tolower);
            if (g == e) ++pass; else ++fail;
        } catch (...) { ++fail; }
    }
    if (out_passed) *out_passed = pass;
    if (out_failed) *out_failed = fail;
    set_err(""); return fail == 0 ? 0 : 1;
    GUARD_END(1)
}

int hash_bench(const char* algo, int size_bytes, int n_blocks, int block_size,
               int outlen,
               double* mean, double* median, double* sd,
               double* ci_lo, double* ci_hi, double* throughput_MiBps) {
    GUARD_BEGIN
    auto a = hashlab::algo_from_string(algo ? algo : "");
    hashlab::Bytes msg(size_bytes);
    for (int i = 0; i < size_bytes; ++i) msg[i] = (uint8_t)(i & 0xFF);
    auto do_one = [&]{ (void)hashlab::hash_bytes(a, msg, (size_t)outlen); };

    using clk = std::chrono::steady_clock;
    auto t0 = clk::now();
    while (std::chrono::duration<double>(clk::now() - t0).count() < 1.0) do_one();

    std::vector<double> per_op_us;
    for (int r = 0; r < n_blocks; ++r) {
        auto a0 = clk::now();
        for (int i = 0; i < block_size; ++i) do_one();
        auto a1 = clk::now();
        per_op_us.push_back(std::chrono::duration<double, std::micro>(a1 - a0).count() / block_size);
    }
    std::sort(per_op_us.begin(), per_op_us.end());
    double m = 0; for (double x : per_op_us) m += x; m /= per_op_us.size();
    double med = per_op_us[per_op_us.size()/2];
    double sq = 0; for (double x : per_op_us) sq += (x - m)*(x - m);
    double s = std::sqrt(sq / std::max<size_t>(1, per_op_us.size() - 1));
    double se = s / std::sqrt((double)per_op_us.size());
    if (mean)   *mean   = m;
    if (median) *median = med;
    if (sd)     *sd     = s;
    if (ci_lo)  *ci_lo  = m - 1.96 * se;
    if (ci_hi)  *ci_hi  = m + 1.96 * se;
    if (throughput_MiBps)
        *throughput_MiBps = (double)size_bytes / (m / 1e6) / (1024.0 * 1024.0);
    set_err(""); return 0;
    GUARD_END(1)
}

} // extern "C"
