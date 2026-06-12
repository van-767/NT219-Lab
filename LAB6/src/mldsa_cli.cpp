// Lab 6 — ML-DSA CLI (keygen / sign / verify / batch / bench / kat / cert).
#include "pq_core.h"

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
using pq::Bytes;

// ─────────── Args ────────────────────────────────────────────────────
struct Args {
    std::string cmd;
    std::map<std::string,std::string> kv;
    std::vector<std::string> pos;
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
            else
                a.kv[s] = "1";
        } else a.pos.push_back(s);
    }
    return a;
}

static void usage() {
    std::cout <<
"MLDSA — Lab 6 ML-DSA CLI (FIPS 204 qua liboqs)\n"
"\n"
"  MLDSA keygen --algo mldsa-44|mldsa-65 --priv FILE --pub FILE\n"
"  MLDSA sign   --priv FILE --in FILE --out FILE\n"
"  MLDSA verify --pub  FILE --in FILE --sig FILE\n"
"  MLDSA batch  --pub  FILE --dir DIR (verify mọi file *.sig vs *.bin)\n"
"  MLDSA bench  --op keygen|sign|verify --algo mldsa-44|mldsa-65\n"
"               [--n 30] [--block 1000] [--size 1024] [--log out.csv]\n"
"  MLDSA kat    [--algo mldsa-44] [--keep]\n"
"  MLDSA cert   --make --ca-priv FILE --ca-pub FILE --subj-pub FILE\n"
"               --subject NAME --out cert.json [--algo mldsa-44]\n"
"  MLDSA cert   --verify --ca-pub FILE --cert cert.json\n";
}

// ─────────── keygen / sign / verify / batch ──────────────────────────
static int cmd_keygen(const Args& a) {
    auto p = pq::dsa_from_string(a.get("--algo", "mldsa-44"));
    pq::mldsa_keygen(p, a.get("--priv"), a.get("--pub"));
    std::cout << "MLDSA keygen OK  algo=" << a.get("--algo","mldsa-44")
              << "  priv=" << a.get("--priv") << "  pub=" << a.get("--pub") << "\n";
    return 0;
}
static int cmd_sign(const Args& a) {
    Bytes msg = pq::read_file(a.get("--in"));
    Bytes sig = pq::mldsa_sign(a.get("--priv"), msg);
    pq::write_file(a.get("--out"), sig);
    std::cout << "MLDSA sign OK  msg=" << msg.size() << "B  sig=" << sig.size() << "B\n";
    return 0;
}
static int cmd_verify(const Args& a) {
    Bytes msg = pq::read_file(a.get("--in"));
    Bytes sig = pq::read_file(a.get("--sig"));
    bool ok = pq::mldsa_verify(a.get("--pub"), msg, sig);
    std::cout << (ok ? "VERIFY OK\n" : "VERIFY FAIL\n");
    return ok ? 0 : 1;
}
static int cmd_batch(const Args& a) {
    std::string dir = a.get("--dir");
    std::string pub = a.get("--pub");
    int ok = 0, total = 0;
    for (auto& e : fs::directory_iterator(dir)) {
        auto p = e.path();
        if (p.extension() != ".sig") continue;
        auto base = p; base.replace_extension(".bin");
        if (!fs::exists(base)) continue;
        ++total;
        if (pq::mldsa_verify(pub, pq::read_file(base.string()), pq::read_file(p.string()))) ++ok;
    }
    std::cout << "Batch: " << ok << "/" << total << " verified\n";
    return (ok == total) ? 0 : 1;
}

// ─────────── bench ────────────────────────────────────────────────────
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
    auto p = pq::dsa_from_string(a.get("--algo", "mldsa-44"));
    int N = a.get_int("--n", 30), B = a.get_int("--block", 1000), size = a.get_int("--size", 1024);
    std::string logp = a.get("--log", "");

    std::string tdir = (fs::temp_directory_path() / "lab6_bench_mldsa").string();
    fs::create_directories(tdir);
    std::string priv = tdir + "/priv.pem", pub = tdir + "/pub.pem";
    Bytes msg(size); for (int i = 0; i < size; ++i) msg[i] = (uint8_t)(i & 0xFF);

    if (op != "keygen") pq::mldsa_keygen(p, priv, pub);
    Bytes sig_pre;
    if (op == "verify") sig_pre = pq::mldsa_sign(priv, msg);

    auto do_one = [&]{
        if (op == "keygen")      pq::mldsa_keygen(p, priv, pub);
        else if (op == "sign")   (void)pq::mldsa_sign(priv, msg);
        else if (op == "verify") (void)pq::mldsa_verify(pub, msg, sig_pre);
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
    std::cout << "MLDSA bench  op=" << op << "  algo=" << a.get("--algo","mldsa-44")
              << "  N=" << N << "  block=" << B << "  msg=" << size << "B\n"
              << "  mean   = " << s.mean   << " μs/op\n"
              << "  median = " << s.median << " μs/op\n"
              << "  stddev = " << s.sd     << " μs\n"
              << "  95% CI = [" << s.ci_lo << ", " << s.ci_hi << "] μs\n"
              << "  throughput ≈ " << (1e6 / s.mean) << " ops/s\n";

    if (!logp.empty()) {
        if (auto pp = fs::path(logp).parent_path(); !pp.empty()) fs::create_directories(pp);
        std::ofstream f(logp);
        f << "op,algo,N,block,msg_size,round,us_per_op\n";
        for (int r = 0; r < N; ++r)
            f << op << "," << a.get("--algo","mldsa-44") << "," << N << "," << B << ","
              << size << "," << r << "," << per_op_us[r] << "\n";
        f << "# summary,mean," << s.mean << ",median," << s.median
          << ",sd," << s.sd << ",ci95_lo," << s.ci_lo << ",ci95_hi," << s.ci_hi << "\n";
        std::cout << "  log → " << logp << "\n";
    }
    return 0;
}

// ─────────── KAT / Negative tests ────────────────────────────────────
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
    auto p = pq::dsa_from_string(a.get("--algo", "mldsa-44"));
    bool keep = a.has("--keep");
    std::string tdir = (fs::temp_directory_path() / "lab6_kat_mldsa").string();
    fs::create_directories(tdir);
    auto P = [&](const char* n){ return tdir + "/" + n; };

    std::cout << "MLDSA KAT — algo=" << a.get("--algo","mldsa-44") << "  workdir=" << tdir << "\n";

    pq::mldsa_keygen(p, P("A_priv.pem"), P("A_pub.pem"));
    pq::mldsa_keygen(p, P("B_priv.pem"), P("B_pub.pem"));
    Bytes msg1 = {'H','e','l','l','o',' ','L','a','b','6'};
    Bytes msg2 = {'O','t','h','e','r'};
    std::vector<CaseResult> R;

    run_case(R, "positive roundtrip", [&]{
        auto sig = pq::mldsa_sign(P("A_priv.pem"), msg1);
        return pq::mldsa_verify(P("A_pub.pem"), msg1, sig);
    });
    auto sig = pq::mldsa_sign(P("A_priv.pem"), msg1);

    run_case(R, "modified message rejected", [&]{
        return !pq::mldsa_verify(P("A_pub.pem"), msg2, sig);
    });
    run_case(R, "modified signature rejected", [&]{
        Bytes bad = sig; if (bad.size() > 8) bad[bad.size()/2] ^= 0x01;
        return !pq::mldsa_verify(P("A_pub.pem"), msg1, bad);
    });
    run_case(R, "wrong public key rejected", [&]{
        return !pq::mldsa_verify(P("B_pub.pem"), msg1, sig);
    });
    run_case(R, "truncated signature rejected", [&]{
        Bytes trunc(sig.begin(), sig.begin() + sig.size()/2);
        return !pq::mldsa_verify(P("A_pub.pem"), msg1, trunc);
    });
    run_case(R, "wrong private key (cross-pair) sign+verify rejected", [&]{
        auto sigB = pq::mldsa_sign(P("B_priv.pem"), msg1);
        return !pq::mldsa_verify(P("A_pub.pem"), msg1, sigB);
    });
    {
        std::string bad_key = P("bad_priv.pem");
        pq::write_file(bad_key, std::string("not a real key"));
        run_case(R, "malformed key file rejected (sign)", [&]{
            try { (void)pq::mldsa_sign(bad_key, msg1); return false; }
            catch (const std::exception&) { return true; }
        });
    }
    // Wrong algorithm identifier (cross-parameter-set) — only if both params buildable.
    auto other = (p == pq::DsaParam::ML_DSA_44) ? pq::DsaParam::ML_DSA_65 : pq::DsaParam::ML_DSA_44;
    run_case(R, "wrong algorithm identifier (cross-param) rejected", [&]{
        pq::mldsa_keygen(other, P("C_priv.pem"), P("C_pub.pem"));
        return !pq::mldsa_verify(P("C_pub.pem"), msg1, sig);
    });

    int ok = 0; for (auto& r : R) if (r.pass) ++ok;
    std::cout << "Summary: " << ok << "/" << R.size() << " cases passed\n";
    if (!keep) { std::error_code ec; fs::remove_all(tdir, ec); }
    else std::cout << "  (--keep) at " << tdir << "\n";
    return (ok == (int)R.size()) ? 0 : 1;
}

// ─────────── PQ Certificate Mini-Project (Lab 6 §3) ─────────────────
// Format:
// {
//   "subject": "...",
//   "algorithm": "ML-DSA-44",
//   "public_key": "<base64 raw>",
//   "issuer": "PQ-CA",
//   "signature": "<base64 ML-DSA(over subject || pubkey)>"
// }
static std::string json_escape(const std::string& s) {
    std::string o; for (char c : s) {
        switch (c) { case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
                     case '\n': o += "\\n"; break; default: o += c; }
    }
    return o;
}
static std::string json_get(const std::string& j, const std::string& key) {
    auto p = j.find("\"" + key + "\"");
    if (p == std::string::npos) throw std::runtime_error("cert missing field: " + key);
    p = j.find(':', p); p = j.find('"', p);
    auto e = j.find('"', p + 1);
    return j.substr(p + 1, e - p - 1);
}

static int cmd_cert(const Args& a) {
    if (a.has("--make")) {
        auto p = pq::dsa_from_string(a.get("--algo", "mldsa-44"));
        std::string ca_priv = a.get("--ca-priv");
        std::string subj_pub_path = a.get("--subj-pub");
        std::string subject = a.get("--subject");
        // Đọc raw pubkey của subject (unwrap PEM).
        auto pub_pem_bytes = pq::read_file(subj_pub_path);
        std::string pub_pem(pub_pem_bytes.begin(), pub_pem_bytes.end());
        std::string lbl = (p == pq::DsaParam::ML_DSA_44 ? "ML-DSA-44 PUBLIC KEY"
                          : p == pq::DsaParam::ML_DSA_65 ? "ML-DSA-65 PUBLIC KEY"
                          : "ML-DSA-87 PUBLIC KEY");
        Bytes subj_pub_raw = pq::pem_unwrap(lbl, pub_pem);

        // To-be-signed: subject (UTF-8) || raw_pubkey.
        Bytes tbs;
        tbs.insert(tbs.end(), subject.begin(), subject.end());
        tbs.insert(tbs.end(), subj_pub_raw.begin(), subj_pub_raw.end());

        Bytes ca_sig = pq::mldsa_sign(ca_priv, tbs);

        std::ostringstream cert;
        cert << "{\n"
             << "  \"subject\": \""    << json_escape(subject)                        << "\",\n"
             << "  \"algorithm\": \""  << pq::dsa_name(p)                             << "\",\n"
             << "  \"public_key\": \"" << pq::b64_encode(subj_pub_raw)                << "\",\n"
             << "  \"issuer\": \"PQ-CA\",\n"
             << "  \"signature\": \""  << pq::b64_encode(ca_sig)                      << "\"\n"
             << "}\n";
        pq::write_file(a.get("--out"), cert.str());
        std::cout << "cert created → " << a.get("--out") << "\n";
        return 0;
    }
    if (a.has("--verify")) {
        auto pem_bytes = pq::read_file(a.get("--cert"));
        std::string cert(pem_bytes.begin(), pem_bytes.end());
        std::string subject = json_get(cert, "subject");
        std::string alg_str = json_get(cert, "algorithm");
        Bytes pubraw = pq::b64_decode(json_get(cert, "public_key"));
        Bytes sig    = pq::b64_decode(json_get(cert, "signature"));

        Bytes tbs;
        tbs.insert(tbs.end(), subject.begin(), subject.end());
        tbs.insert(tbs.end(), pubraw.begin(), pubraw.end());

        bool ok = pq::mldsa_verify(a.get("--ca-pub"), tbs, sig);
        std::cout << (ok ? "CERT VERIFY OK"   : "CERT VERIFY FAIL")
                  << "  subject=" << subject << "  alg=" << alg_str << "\n";
        return ok ? 0 : 1;
    }
    usage(); return 2;
}

// ─────────── main ────────────────────────────────────────────────────
int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc < 2) { usage(); return 0; }
    try {
        Args a = parse(argc, argv);
        if (a.cmd == "keygen") return cmd_keygen(a);
        if (a.cmd == "sign")   return cmd_sign(a);
        if (a.cmd == "verify") return cmd_verify(a);
        if (a.cmd == "batch")  return cmd_batch(a);
        if (a.cmd == "bench")  return cmd_bench(a);
        if (a.cmd == "kat")    return cmd_kat(a);
        if (a.cmd == "cert")   return cmd_cert(a);
        if (a.cmd == "-h" || a.cmd == "--help" || a.cmd == "help") { usage(); return 0; }
        usage(); return 2;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
