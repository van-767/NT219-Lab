// Lab 4 Task 1 - hashtool CLI: digest / kat / bench.
#include "hash_core.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cmath>

namespace fs = std::filesystem;
using hashlab::Bytes;

struct Args {
    std::string cmd;
    std::map<std::string,std::string> kv;
    bool has(const std::string& k) const { return kv.count(k); }
    std::string get(const std::string& k, const std::string& d="") const {
        auto it = kv.find(k); return it == kv.end() ? d : it->second;
    }
    int get_int(const std::string& k, int d) const {
        auto it = kv.find(k); return it == kv.end() ? d : std::stoi(it->second);
    }
};
static Args parse(int argc, char** argv) {
    Args a; if (argc >= 2) a.cmd = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string s = argv[i];
        if (s.rfind("--", 0) == 0) {
            if (i + 1 < argc && std::string(argv[i+1]).rfind("--", 0) != 0)
                a.kv[s] = argv[++i];
            else a.kv[s] = "1";
        }
    }
    return a;
}

static void usage() {
    std::cout <<
"hashtool - Lab 4 Task 1 (SHA-2/3/SHAKE through Crypto++)\n"
"\n"
"  hashtool digest --algo <ALG> [--in FILE] [--text STR] [--outlen N]\n"
"                  [--out FILE] [--encode hex|raw]\n"
"  hashtool kat    --kat FILE\n"
"  hashtool bench  --algo <ALG> [--size BYTES] [--n 30] [--block 1000]\n"
"                  [--outlen 32] [--log out.csv]\n"
"\n"
"ALG: sha224|sha256|sha384|sha512|sha3-224|sha3-256|sha3-384|sha3-512\n"
"   | shake128|shake256  (XOF, requires --outlen)\n";
}

// digest
static int cmd_digest(const Args& a) {
    auto algo = hashlab::algo_from_string(a.get("--algo"));
    size_t outlen = (size_t)a.get_int("--outlen", 32);
    std::string enc = a.get("--encode", "hex");
    if (enc != "hex" && enc != "raw") {
        std::cerr << "Invalid --encode. Use hex or raw.\n";
        return 2;
    }
    Bytes d;
    if (a.has("--in")) {
        d = hashlab::hash_file_streamed(algo, a.get("--in"), outlen);
    } else if (a.has("--text")) {
        const std::string& t = a.kv.at("--text");
        d = hashlab::hash_bytes(algo, Bytes(t.begin(), t.end()), outlen);
    } else { std::cerr << "Need --in FILE or --text STR\n"; return 2; }

    if (a.has("--out")) {
        if (enc == "raw") hashlab::write_file(a.get("--out"), d);
        else hashlab::write_file(a.get("--out"), hashlab::hex_encode(d) + "\n");
    } else {
        std::cout << (enc == "raw" ? std::string(d.begin(), d.end())
                                    : hashlab::hex_encode(d)) << "\n";
    }
    return 0;
}

// kat
static std::string json_get_str(const std::string& j, const std::string& key) {
    auto p = j.find("\"" + key + "\"");
    if (p == std::string::npos) throw std::runtime_error("missing field: " + key);
    p = j.find(':', p); p = j.find('"', p);
    auto e = j.find('"', p + 1);
    return j.substr(p + 1, e - p - 1);
}
static int json_get_int(const std::string& j, const std::string& key, int def) {
    auto p = j.find("\"" + key + "\"");
    if (p == std::string::npos) return def;
    p = j.find(':', p);
    auto q = p + 1; while (q < j.size() && (j[q] == ' ' || j[q] == '\t')) ++q;
    try { return std::stoi(j.substr(q)); } catch (...) { return def; }
}
static std::vector<std::string> split_tests(const std::string& json) {
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

static int cmd_kat(const Args& a) {
    std::string path = a.get("--kat");
    if (path.empty()) { usage(); return 2; }
    auto bytes = hashlab::read_file(path);
    std::string json(bytes.begin(), bytes.end());
    auto cases = split_tests(json);
    int pass = 0, fail = 0;
    for (auto& tc : cases) {
        std::string name = json_get_str(tc, "name");
        std::string algo_s = json_get_str(tc, "algo");
        std::string msg_hex = json_get_str(tc, "msg_hex");
        std::string exp_hex = json_get_str(tc, "expected_hex");
        int outlen = json_get_int(tc, "outlen", 0);
        bool ok = false; std::string why;
        try {
            auto algo = hashlab::algo_from_string(algo_s);
            Bytes msg = hashlab::hex_decode(msg_hex);
            Bytes got = hashlab::hash_bytes(algo, msg, (size_t)outlen);
            std::string a1 = hashlab::hex_encode(got), b1 = exp_hex;
            std::transform(a1.begin(), a1.end(), a1.begin(), ::tolower);
            std::transform(b1.begin(), b1.end(), b1.begin(), ::tolower);
            ok = (a1 == b1);
            if (!ok) why = "digest mismatch";
        } catch (const std::exception& e) { why = e.what(); }
        if (ok) { ++pass; std::cout << "  PASS  " << name << "\n"; }
        else    { ++fail; std::cout << "  FAIL  " << name << "  (" << why << ")\n"; }
    }
    std::cout << "\nSummary: " << pass << " passed, " << fail << " failed, " << cases.size() << " total.\n";
    return fail == 0 ? 0 : 1;
}

// bench
struct Stat { double mean=0, median=0, sd=0, ci_lo=0, ci_hi=0; };
static Stat stats(std::vector<double>& v) {
    Stat s; if (v.empty()) return s;
    std::sort(v.begin(), v.end());
    s.median = v[v.size()/2];
    double sum = 0; for (double x : v) sum += x; s.mean = sum / v.size();
    double sq = 0; for (double x : v) sq += (x - s.mean)*(x - s.mean);
    s.sd = std::sqrt(sq / std::max<size_t>(1, v.size() - 1));
    double se = s.sd / std::sqrt((double)v.size());
    s.ci_lo = s.mean - 1.96 * se; s.ci_hi = s.mean + 1.96 * se;
    return s;
}

static int cmd_bench(const Args& a) {
    auto algo = hashlab::algo_from_string(a.get("--algo"));
    int N = a.get_int("--n", 30), B = a.get_int("--block", 1000);
    size_t size = (size_t)a.get_int("--size", 1024);
    size_t outlen = (size_t)a.get_int("--outlen", 32);
    std::string logp = a.get("--log", "");

    Bytes msg(size); for (size_t i = 0; i < size; ++i) msg[i] = (uint8_t)(i & 0xFF);
    auto do_one = [&]{ (void)hashlab::hash_bytes(algo, msg, outlen); };

    using clk = std::chrono::steady_clock;
    auto t0 = clk::now();
    while (std::chrono::duration<double>(clk::now() - t0).count() < 1.0) do_one();

    std::vector<double> per_op_us;
    for (int r = 0; r < N; ++r) {
        auto a0 = clk::now();
        for (int i = 0; i < B; ++i) do_one();
        auto a1 = clk::now();
        per_op_us.push_back(std::chrono::duration<double, std::micro>(a1 - a0).count() / B);
    }
    auto s = stats(per_op_us);
    double throughput_MBps = (double)size / (s.mean / 1e6) / (1024.0 * 1024.0);

    std::cout << "hashtool bench  algo=" << hashlab::algo_to_string(algo)
              << "  N=" << N << "  block=" << B << "  size=" << size << "B\n"
              << "  mean   = " << s.mean   << " us/op\n"
              << "  median = " << s.median << " us/op\n"
              << "  stddev = " << s.sd     << " us\n"
              << "  95% CI = [" << s.ci_lo << ", " << s.ci_hi << "] us\n"
              << "  throughput ~= " << throughput_MBps << " MiB/s\n";

    if (!logp.empty()) {
        if (auto pp = fs::path(logp).parent_path(); !pp.empty()) fs::create_directories(pp);
        std::ofstream f(logp);
        f << "algo,N,block,msg_size,round,us_per_op\n";
        for (int r = 0; r < N; ++r)
            f << hashlab::algo_to_string(algo) << "," << N << "," << B << ","
              << size << "," << r << "," << per_op_us[r] << "\n";
        f << "# summary,mean," << s.mean << ",median," << s.median
          << ",sd," << s.sd << ",ci95_lo," << s.ci_lo << ",ci95_hi," << s.ci_hi
          << ",throughput_MiBps," << throughput_MBps << "\n";
        std::cout << "  log: " << logp << "\n";
    }
    return 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 2) { usage(); return 0; }
    try {
        Args a = parse(argc, argv);
        if (a.cmd == "digest") return cmd_digest(a);
        if (a.cmd == "kat")    return cmd_kat(a);
        if (a.cmd == "bench")  return cmd_bench(a);
        if (a.cmd == "-h" || a.cmd == "--help" || a.cmd == "help") { usage(); return 0; }
        usage(); return 2;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
