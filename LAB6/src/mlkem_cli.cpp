// Lab 6 — ML-KEM CLI (keygen / encaps / decaps / bench / kat).
#include "pq_core.h"

#include <chrono>
#include <cstdio>
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
using pq::Bytes;

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
"MLKEM — Lab 6 ML-KEM CLI (FIPS 203 qua liboqs)\n"
"\n"
"  MLKEM keygen --algo mlkem-512|mlkem-768|mlkem-1024 --priv FILE --pub FILE\n"
"  MLKEM encaps --pub  FILE --ct FILE --ss FILE\n"
"  MLKEM decaps --priv FILE --ct FILE --ss FILE\n"
"  MLKEM bench  --op keygen|encaps|decaps --algo mlkem-512|...\n"
"               [--n 30] [--block 1000] [--log out.csv]\n"
"  MLKEM kat    [--algo mlkem-512] [--keep]\n";
}

static int cmd_keygen(const Args& a) {
    auto p = pq::kem_from_string(a.get("--algo", "mlkem-512"));
    pq::mlkem_keygen(p, a.get("--priv"), a.get("--pub"));
    std::cout << "MLKEM keygen OK  algo=" << a.get("--algo","mlkem-512") << "\n";
    return 0;
}
static int cmd_encaps(const Args& a) {
    pq::mlkem_encaps(a.get("--pub"), a.get("--ct"), a.get("--ss"));
    std::cout << "MLKEM encaps OK  ct=" << a.get("--ct") << "  ss=" << a.get("--ss") << "\n";
    return 0;
}
static int cmd_decaps(const Args& a) {
    pq::mlkem_decaps(a.get("--priv"), a.get("--ct"), a.get("--ss"));
    std::cout << "MLKEM decaps OK  ss=" << a.get("--ss") << "\n";
    return 0;
}

// ─────────── bench ────────────────────────────────────────────────
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
    std::string op = a.get("--op");
    if (op.empty()) { usage(); return 2; }
    auto p = pq::kem_from_string(a.get("--algo", "mlkem-512"));
    int N = a.get_int("--n", 30), B = a.get_int("--block", 1000);
    std::string logp = a.get("--log", "");

    std::string tdir = (fs::temp_directory_path() / "lab6_bench_mlkem").string();
    fs::create_directories(tdir);
    std::string priv = tdir + "/priv.pem", pub = tdir + "/pub.pem";
    std::string ctp = tdir + "/ct.bin", ssp = tdir + "/ss.bin";

    if (op != "keygen") pq::mlkem_keygen(p, priv, pub);
    if (op == "decaps") pq::mlkem_encaps(pub, ctp, ssp);  // pre-compute ct + ss

    auto do_one = [&]{
        if (op == "keygen")      pq::mlkem_keygen(p, priv, pub);
        else if (op == "encaps") pq::mlkem_encaps(pub, ctp, ssp);
        else if (op == "decaps") pq::mlkem_decaps(priv, ctp, ssp);
        else throw std::runtime_error("Unknown --op");
    };

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
    std::cout << "MLKEM bench  op=" << op << "  algo=" << a.get("--algo","mlkem-512")
              << "  N=" << N << "  block=" << B << "\n"
              << "  mean   = " << s.mean   << " μs/op\n"
              << "  median = " << s.median << " μs/op\n"
              << "  stddev = " << s.sd     << " μs\n"
              << "  95% CI = [" << s.ci_lo << ", " << s.ci_hi << "] μs\n"
              << "  throughput ≈ " << (1e6 / s.mean) << " ops/s\n";

    if (!logp.empty()) {
        if (auto pp = fs::path(logp).parent_path(); !pp.empty()) fs::create_directories(pp);
        std::ofstream f(logp);
        f << "op,algo,N,block,round,us_per_op\n";
        for (int r = 0; r < N; ++r)
            f << op << "," << a.get("--algo","mlkem-512") << "," << N << "," << B << ","
              << r << "," << per_op_us[r] << "\n";
        f << "# summary,mean," << s.mean << ",median," << s.median
          << ",sd," << s.sd << ",ci95_lo," << s.ci_lo << ",ci95_hi," << s.ci_hi << "\n";
        std::cout << "  log → " << logp << "\n";
    }
    return 0;
}

// ─────────── KAT / Negative tests ─────────────────────────────────
namespace {
struct CaseResult { std::string name; bool pass; std::string note; };
void run_case(std::vector<CaseResult>& v, const std::string& name,
              const std::function<bool()>& fn) {
    bool ok = false; std::string note;
    try { ok = fn(); }
    catch (const std::exception& e) { ok = false; note = e.what(); }
    v.push_back({name, ok, note});
    std::cout << (ok ? "  PASS  " : "  FAIL  ") << name;
    if (!note.empty()) std::cout << "  (" << note << ")";
    std::cout << "\n";
}
} // anon

static int cmd_kat(const Args& a) {
    auto p = pq::kem_from_string(a.get("--algo", "mlkem-512"));
    bool keep = a.has("--keep");
    std::string tdir = (fs::temp_directory_path() / "lab6_kat_mlkem").string();
    fs::create_directories(tdir);
    auto P = [&](const char* n){ return tdir + "/" + n; };

    std::cout << "MLKEM KAT — algo=" << a.get("--algo","mlkem-512") << "  workdir=" << tdir << "\n";

    pq::mlkem_keygen(p, P("A_priv.pem"), P("A_pub.pem"));
    pq::mlkem_keygen(p, P("B_priv.pem"), P("B_pub.pem"));

    std::vector<CaseResult> R;

    // 1. Positive: encaps + decaps cùng pair → shared secret giống nhau.
    run_case(R, "positive encaps/decaps match", [&]{
        pq::mlkem_encaps(P("A_pub.pem"), P("ct.bin"), P("ss_send.bin"));
        pq::mlkem_decaps(P("A_priv.pem"), P("ct.bin"), P("ss_recv.bin"));
        return pq::read_file(P("ss_send.bin")) == pq::read_file(P("ss_recv.bin"));
    });

    // 2. Wrong private key (B priv với ct của A) → KEM trả ra shared secret KHÁC
    //    (do FO transform — không throw, nhưng SS khác → bài này coi như fail).
    run_case(R, "wrong private key produces different SS", [&]{
        pq::mlkem_decaps(P("B_priv.pem"), P("ct.bin"), P("ss_wrong.bin"));
        return pq::read_file(P("ss_send.bin")) != pq::read_file(P("ss_wrong.bin"));
    });

    // 3. Modified ciphertext → SS khác hoặc decaps throw.
    run_case(R, "modified ciphertext yields different SS", [&]{
        Bytes ct = pq::read_file(P("ct.bin"));
        ct[ct.size()/2] ^= 0x01;
        pq::write_file(P("ct_bad.bin"), ct);
        try {
            pq::mlkem_decaps(P("A_priv.pem"), P("ct_bad.bin"), P("ss_bad.bin"));
            return pq::read_file(P("ss_send.bin")) != pq::read_file(P("ss_bad.bin"));
        } catch (const std::exception&) { return true; }  // throw cũng OK
    });

    // 4. Truncated ciphertext → throw.
    run_case(R, "truncated ciphertext rejected", [&]{
        Bytes ct = pq::read_file(P("ct.bin"));
        ct.resize(ct.size() / 2);
        pq::write_file(P("ct_short.bin"), ct);
        try { pq::mlkem_decaps(P("A_priv.pem"), P("ct_short.bin"), P("ss_short.bin")); return false; }
        catch (const std::exception&) { return true; }
    });

    // 5. Malformed key file → throw.
    {
        std::string bad = P("bad_priv.pem");
        pq::write_file(bad, std::string("not a real key"));
        run_case(R, "malformed key file rejected (decaps)", [&]{
            try { pq::mlkem_decaps(bad, P("ct.bin"), P("ss_dummy.bin")); return false; }
            catch (const std::exception&) { return true; }
        });
    }

    // 6. Wrong algorithm identifier (cross-param) → throw vì length mismatch.
    auto other = (p == pq::KemParam::ML_KEM_512) ? pq::KemParam::ML_KEM_768 : pq::KemParam::ML_KEM_512;
    run_case(R, "wrong algorithm identifier (cross-param) rejected", [&]{
        pq::mlkem_keygen(other, P("C_priv.pem"), P("C_pub.pem"));
        try { pq::mlkem_decaps(P("C_priv.pem"), P("ct.bin"), P("ss_x.bin")); return false; }
        catch (const std::exception&) { return true; }
    });

    int ok = 0; for (auto& r : R) if (r.pass) ++ok;
    std::cout << "Summary: " << ok << "/" << R.size() << " cases passed\n";
    if (!keep) { std::error_code ec; fs::remove_all(tdir, ec); }
    else std::cout << "  (--keep) at " << tdir << "\n";
    return (ok == (int)R.size()) ? 0 : 1;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc < 2) { usage(); return 0; }
    try {
        Args a = parse(argc, argv);
        if (a.cmd == "keygen") return cmd_keygen(a);
        if (a.cmd == "encaps") return cmd_encaps(a);
        if (a.cmd == "decaps") return cmd_decaps(a);
        if (a.cmd == "bench")  return cmd_bench(a);
        if (a.cmd == "kat")    return cmd_kat(a);
        if (a.cmd == "-h" || a.cmd == "--help" || a.cmd == "help") { usage(); return 0; }
        usage(); return 2;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
