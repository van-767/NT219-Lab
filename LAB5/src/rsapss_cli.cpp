// Lab 5 — RSA-PSS CLI: keygen / sign / verify / batch / bench.
#include "rsapss_core.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <functional>

using rsapss::Bytes;
namespace fs = std::filesystem;

struct Args {
    std::string cmd;
    std::map<std::string, std::string> kv;
    std::vector<std::string> flags;
    bool has(const std::string& k) const {
        return kv.count(k) || std::find(flags.begin(), flags.end(), k) != flags.end();
    }
    std::string get(const std::string& k, const std::string& def = "") const {
        auto it = kv.find(k); return it == kv.end() ? def : it->second;
    }
    int get_int(const std::string& k, int def) const {
        auto it = kv.find(k); return it == kv.end() ? def : std::stoi(it->second);
    }
};
static Args parse(int argc, char** argv) {
    Args a;
    if (argc >= 2) a.cmd = argv[1];
    for (int i = 2; i < argc; ++i) {
        std::string t = argv[i];
        if (t.rfind("--", 0) == 0) {
            if (i + 1 < argc && std::string(argv[i+1]).rfind("--", 0) != 0) a.kv[t] = argv[++i];
            else a.flags.push_back(t);
        }
    }
    return a;
}

static void usage() {
    std::cerr <<
"RSA-PSS tool (Lab 5)\n"
"Usage:\n"
"  RSAPSS keygen --bits 3072|4096 --priv FILE --pub FILE [--format pem|der]\n"
"  RSAPSS sign   --priv FILE --in FILE --out FILE\n"
"                [--hash sha256|sha384|sha512] [--salt-len N (-1=hashLen)] [--encode raw|base64]\n"
"  RSAPSS verify --pub  FILE --in FILE --sig FILE\n"
"                [--hash ...] [--salt-len N] [--encode raw|base64]\n"
"  RSAPSS batch  --pub  FILE --dir DIR [--hash ...] [--salt-len N] [--encode ...]\n"
"  RSAPSS bench  --op keygen|sign|verify [--bits 3072] [--n 30] [--block 1000]\n"
"                [--size 1024] [--hash sha256] [--log out.csv]\n"
"  RSAPSS kat    [--bits 3072] [--keep]\n"
"                Chạy bộ Correctness + Negative test tự động (PASS/FAIL per case + summary).\n";
}

static rsapss::SigEncoding parse_enc(const std::string& s) {
    return s.empty() ? rsapss::SigEncoding::Raw : rsapss::sigenc_from_string(s);
}
struct Stat { double mean, median, sd, ci95_lo, ci95_hi; };
static Stat compute_stat(std::vector<double>& v) {
    Stat s{};
    if (v.empty()) return s;
    double sum = 0; for (double x : v) sum += x;
    s.mean = sum / v.size();
    auto v2 = v; std::sort(v2.begin(), v2.end());
    s.median = v2.size() % 2 ? v2[v2.size()/2]
                              : 0.5 * (v2[v2.size()/2 - 1] + v2[v2.size()/2]);
    double var = 0; for (double x : v) var += (x - s.mean) * (x - s.mean);
    s.sd = v.size() > 1 ? std::sqrt(var / (v.size() - 1)) : 0;
    double se = s.sd / std::sqrt((double)v.size());
    s.ci95_lo = s.mean - 1.96 * se;
    s.ci95_hi = s.mean + 1.96 * se;
    return s;
}

static int cmd_keygen(const Args& a) {
    int bits = a.get_int("--bits", 3072);
    auto fmt = rsapss::keyformat_from_string(a.get("--format", "pem"));
    auto priv = a.get("--priv"), pub = a.get("--pub");
    if (priv.empty() || pub.empty()) { usage(); return 2; }
    rsapss::keygen(bits, priv, pub, fmt);
    std::cout << "[OK] RSA-" << bits << " PSS keypair → " << priv << ", " << pub << "\n";
    return 0;
}

static int cmd_sign(const Args& a) {
    auto priv = a.get("--priv"), in = a.get("--in"), out = a.get("--out");
    if (priv.empty() || in.empty() || out.empty()) { usage(); return 2; }
    auto enc  = parse_enc(a.get("--encode", "raw"));
    auto hash = a.get("--hash", "sha256");
    int  slen = a.get_int("--salt-len", -1);
    auto msg  = rsapss::read_file(in);
    auto sig  = rsapss::sign_bytes(priv, msg, hash, slen, enc);
    rsapss::write_file(out, sig);
    if (enc == rsapss::SigEncoding::Base64) {
        std::string s(sig.begin(), sig.end());
        std::cout << "[OK] signature (base64): " << s << "\n";
    } else {
        std::cout << "[OK] signature (hex): " << rsapss::hex_encode(sig) << "\n";
    }
    return 0;
}

static int cmd_verify(const Args& a) {
    auto pub = a.get("--pub"), in = a.get("--in"), sigp = a.get("--sig");
    if (pub.empty() || in.empty() || sigp.empty()) { usage(); return 2; }
    auto enc  = parse_enc(a.get("--encode", "raw"));
    auto hash = a.get("--hash", "sha256");
    int  slen = a.get_int("--salt-len", -1);
    auto msg  = rsapss::read_file(in);
    auto sig  = rsapss::read_file(sigp);
    bool ok = rsapss::verify_bytes(pub, msg, sig, hash, slen, enc);
    std::cout << (ok ? "[OK] Signature valid\n" : "[FAIL] Signature INVALID\n");
    return ok ? 0 : 1;
}

static int cmd_batch(const Args& a) {
    auto pub = a.get("--pub"), dir = a.get("--dir");
    if (pub.empty() || dir.empty()) { usage(); return 2; }
    auto enc  = parse_enc(a.get("--encode", "raw"));
    auto hash = a.get("--hash", "sha256");
    int  slen = a.get_int("--salt-len", -1);
    int total = 0, ok = 0;
    for (auto& ent : fs::directory_iterator(dir)) {
        if (!ent.is_regular_file()) continue;
        auto p = ent.path();
        if (p.extension() != ".sig") continue;
        auto base = p; base.replace_extension("");
        auto msg_path = base.string() + ".bin";
        if (!fs::exists(msg_path)) {
            std::cout << "SKIP  " << p.filename().string() << " (missing .bin)\n";
            continue;
        }
        ++total;
        auto msg = rsapss::read_file(msg_path);
        auto sig = rsapss::read_file(p.string());
        bool good = rsapss::verify_bytes(pub, msg, sig, hash, slen, enc);
        std::cout << (good ? "PASS  " : "FAIL  ") << p.filename().string() << "\n";
        if (good) ++ok;
    }
    std::cout << "Summary: " << ok << "/" << total << " passed\n";
    return (ok == total) ? 0 : 1;
}

static int cmd_bench(const Args& a) {
    std::string op = a.get("--op");
    if (op.empty()) { usage(); return 2; }
    int bits = a.get_int("--bits", 3072);
    int N = a.get_int("--n", 30);
    int B = a.get_int("--block", 1000);
    int size = a.get_int("--size", 1024);
    std::string hash = a.get("--hash", "sha256");
    std::string logp = a.get("--log", "");

    std::string tdir = (fs::temp_directory_path() / "lab5_bench_rsapss").string();
    fs::create_directories(tdir);
    std::string priv = tdir + "/bench_priv.pem";
    std::string pub  = tdir + "/bench_pub.pem";
    Bytes msg(size); for (int i = 0; i < size; ++i) msg[i] = (uint8_t)(i & 0xFF);

    if (op != "keygen") rsapss::keygen(bits, priv, pub, rsapss::KeyFormat::PEM);
    Bytes presig;
    if (op == "verify") presig = rsapss::sign_bytes(priv, msg, hash, -1, rsapss::SigEncoding::Raw);

    auto do_one = [&]() {
        if (op == "keygen")      rsapss::keygen(bits, priv, pub, rsapss::KeyFormat::PEM);
        else if (op == "sign")   (void)rsapss::sign_bytes(priv, msg, hash, -1, rsapss::SigEncoding::Raw);
        else if (op == "verify") (void)rsapss::verify_bytes(pub, msg, presig, hash, -1, rsapss::SigEncoding::Raw);
        else throw std::runtime_error("Unknown --op (keygen|sign|verify)");
    };

    // Warm-up 1s (giảm còn 0.2s cho keygen vì 1 op đã có thể vài giây).
    using clk = std::chrono::steady_clock;
    double warm = (op == "keygen") ? 0.2 : 1.0;
    auto t_warm = clk::now();
    while (std::chrono::duration<double>(clk::now() - t_warm).count() < warm) do_one();

    // Mặc định block=1000; user nên giảm cho keygen (ví dụ --block 1).
    std::vector<double> per_op_us; per_op_us.reserve(N);
    for (int r = 0; r < N; ++r) {
        auto t0 = clk::now();
        for (int i = 0; i < B; ++i) do_one();
        auto t1 = clk::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count() / B;
        per_op_us.push_back(us);
    }
    auto s = compute_stat(per_op_us);

    std::cout << "RSA-PSS bench  op=" << op
              << "  bits=" << bits
              << "  N=" << N << "  block=" << B
              << "  msg=" << size << "B  hash=" << hash << "\n"
              << "  mean   = " << s.mean   << " µs/op\n"
              << "  median = " << s.median << " µs/op\n"
              << "  stddev = " << s.sd     << " µs\n"
              << "  95% CI = [" << s.ci95_lo << ", " << s.ci95_hi << "] µs\n"
              << "  throughput ≈ " << (1e6 / s.mean) << " ops/s\n";

    if (!logp.empty()) {
        if (auto pp = fs::path(logp).parent_path(); !pp.empty()) fs::create_directories(pp);
        std::ofstream f(logp);
        f << "op,bits,N,block,msg_size,hash,round,us_per_op\n";
        for (int r = 0; r < N; ++r)
            f << op << "," << bits << "," << N << "," << B << "," << size << "," << hash << ","
              << r << "," << per_op_us[r] << "\n";
        f << "# summary,mean," << s.mean << ",median," << s.median
          << ",sd," << s.sd << ",ci95_lo," << s.ci95_lo << ",ci95_hi," << s.ci95_hi << "\n";
        std::cout << "  log → " << logp << "\n";
    }
    return 0;
}

// ── KAT / Negative tests (spec Lab 5 §3) ─────────────────────────────────
namespace {
struct CaseResult { std::string name; bool pass; std::string note; };
void run_case(std::vector<CaseResult>& v, const std::string& name,
              const std::function<bool()>& fn) {
    bool ok = false; std::string note;
    try { ok = fn(); }
    catch (const std::exception& e) { ok = false; note = std::string("exception: ") + e.what(); }
    v.push_back({name, ok, note});
    std::cout << (ok ? "  PASS  " : "  FAIL  ") << name;
    if (!note.empty()) std::cout << "  (" << note << ")";
    std::cout << "\n";
}
} // anon

static int cmd_kat(const Args& a) {
    int bits = a.get_int("--bits", 3072);
    bool keep = a.has("--keep");

    std::string tdir = (fs::temp_directory_path() / "lab5_kat_rsapss").string();
    fs::create_directories(tdir);
    auto P = [&](const char* n){ return tdir + "/" + n; };

    std::cout << "RSA-PSS KAT — bits=" << bits << "  workdir=" << tdir << "\n";

    rsapss::keygen(bits, P("A_priv.pem"), P("A_pub.pem"), rsapss::KeyFormat::PEM);
    rsapss::keygen(bits, P("B_priv.pem"), P("B_pub.pem"), rsapss::KeyFormat::PEM);
    Bytes msg1 = {'H','e','l','l','o',' ','L','a','b','5'};
    Bytes msg2 = {'O','t','h','e','r',' ','m','s','g'};

    std::vector<CaseResult> R;

    // 1. Positive roundtrip qua 2 encoding.
    for (auto enc : {rsapss::SigEncoding::Raw, rsapss::SigEncoding::Base64}) {
        std::string ename = (enc == rsapss::SigEncoding::Raw ? "raw" : "base64");
        run_case(R, "positive roundtrip encode=" + ename, [&]{
            auto sig = rsapss::sign_bytes(P("A_priv.pem"), msg1, "sha256", -1, enc);
            return rsapss::verify_bytes(P("A_pub.pem"), msg1, sig, "sha256", -1, enc);
        });
    }

    auto sig_raw = rsapss::sign_bytes(P("A_priv.pem"), msg1, "sha256", -1, rsapss::SigEncoding::Raw);

    // 2. Modified message → FAIL.
    run_case(R, "modified message rejected", [&]{
        return !rsapss::verify_bytes(P("A_pub.pem"), msg2, sig_raw, "sha256", -1, rsapss::SigEncoding::Raw);
    });

    // 3. Modified signature (lật 1 bit) → FAIL.
    run_case(R, "modified signature rejected", [&]{
        Bytes bad = sig_raw;
        if (bad.size() > 8) bad[bad.size()/2] ^= 0x01;
        return !rsapss::verify_bytes(P("A_pub.pem"), msg1, bad, "sha256", -1, rsapss::SigEncoding::Raw);
    });

    // 4. Wrong public key → FAIL.
    run_case(R, "wrong public key rejected", [&]{
        return !rsapss::verify_bytes(P("B_pub.pem"), msg1, sig_raw, "sha256", -1, rsapss::SigEncoding::Raw);
    });

    // 5. Wrong hash (ký sha256, verify sha384) → FAIL.
    run_case(R, "wrong hash function rejected", [&]{
        return !rsapss::verify_bytes(P("A_pub.pem"), msg1, sig_raw, "sha384", -1, rsapss::SigEncoding::Raw);
    });

    // 6. Wrong salt-len → FAIL (ký salt=32 (hashLen), verify salt=16).
    run_case(R, "wrong salt-len rejected", [&]{
        return !rsapss::verify_bytes(P("A_pub.pem"), msg1, sig_raw, "sha256", 16, rsapss::SigEncoding::Raw);
    });

    // 7. Encoding mismatch (ký raw, verify như base64) → FAIL closed.
    run_case(R, "encoding mismatch rejected", [&]{
        return !rsapss::verify_bytes(P("A_pub.pem"), msg1, sig_raw, "sha256", -1, rsapss::SigEncoding::Base64);
    });

    // 8. Malformed key file.
    {
        std::string bad_key = P("bad_priv.pem");
        rsapss::write_file(bad_key, std::string("not a real key"));
        run_case(R, "malformed key file rejected (sign)", [&]{
            try { (void)rsapss::sign_bytes(bad_key, msg1, "sha256", -1, rsapss::SigEncoding::Raw); return false; }
            catch (const std::exception&) { return true; }
        });
    }

    // 9. Truncated sig.
    run_case(R, "truncated signature rejected", [&]{
        Bytes trunc(sig_raw.begin(), sig_raw.begin() + sig_raw.size()/2);
        return !rsapss::verify_bytes(P("A_pub.pem"), msg1, trunc, "sha256", -1, rsapss::SigEncoding::Raw);
    });

    // 10. Policy: từ chối keygen <3072.
    run_case(R, "keygen <3072 bits rejected (spec)", [&]{
        try { rsapss::keygen(2048, P("weak_priv.pem"), P("weak_pub.pem"), rsapss::KeyFormat::PEM); return false; }
        catch (const std::exception&) { return true; }
    });

    // 11. Wrong algorithm identifier (cross-key-size) → FAIL.
    //    Spec §3 mandate: chữ ký từ modulus này phải fail khi verify bằng
    //    public key có modulus size khác (3072 vs 4096).
    run_case(R, "wrong algorithm identifier (cross-key-size) rejected", [&]{
        int other_bits = (bits == 3072) ? 4096 : 3072;
        rsapss::keygen(other_bits, P("C_priv.pem"), P("C_pub.pem"), rsapss::KeyFormat::PEM);
        return !rsapss::verify_bytes(P("C_pub.pem"), msg1, sig_raw, "sha256", -1, rsapss::SigEncoding::Raw);
    });

    int ok = 0; for (auto& r : R) if (r.pass) ++ok;
    std::cout << "Summary: " << ok << "/" << R.size() << " cases passed\n";
    if (!keep) { std::error_code ec; fs::remove_all(tdir, ec); }
    else std::cout << "  (--keep) artifacts left at " << tdir << "\n";
    return (ok == (int)R.size()) ? 0 : 1;
}

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
        if (a.cmd == "-h" || a.cmd == "--help" || a.cmd == "help") { usage(); return 0; }
        usage(); return 2;
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
        return 1;
    }
}
