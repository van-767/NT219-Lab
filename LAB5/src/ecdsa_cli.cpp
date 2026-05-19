// Lab 5 — ECDSA CLI. Hợp nhất: keygen / sign / verify / batch / bench.
#include "ecdsa_core.h"

#include <openssl/err.h>
#include <openssl/crypto.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <chrono>
#include <algorithm>
#include <cmath>
#include <filesystem>
#include <functional>

using ecdsa::Bytes;
namespace fs = std::filesystem;

// ── tiny argparse ─────────────────────────────────────────────────────────
struct Args {
    std::string cmd;
    std::map<std::string, std::string> kv;
    std::vector<std::string> flags;
    bool has(const std::string& k) const { return kv.count(k) || std::find(flags.begin(), flags.end(), k) != flags.end(); }
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
            if (i + 1 < argc && std::string(argv[i+1]).rfind("--", 0) != 0) {
                a.kv[t] = argv[++i];
            } else a.flags.push_back(t);
        }
    }
    return a;
}

static void usage() {
    std::cerr <<
"ECDSA tool (Lab 5)\n"
"Usage:\n"
"  ECDSA keygen --algo ecdsa-p256|ecdsa-p384 --priv FILE --pub FILE [--format pem|der]\n"
"  ECDSA sign   --priv FILE --in FILE  --out FILE  [--hash sha256|sha384] [--encode raw|der|base64]\n"
"  ECDSA verify --pub  FILE --in FILE  --sig FILE  [--hash sha256|sha384] [--encode raw|der|base64]\n"
"  ECDSA batch  --pub  FILE --dir DIR  [--hash ...] [--encode ...]\n"
"      Dir chứa từng cặp <name>.bin (message) + <name>.sig.\n"
"  ECDSA bench  --op keygen|sign|verify --algo ecdsa-p256|ecdsa-p384\n"
"               [--n 30] [--block 1000] [--size 1024] [--log out.csv]\n"
"               Warmup 1s, sau đó N round, mỗi round thực hiện BLOCK ops, đo mean/median/sd/95%CI per op.\n"
"  ECDSA kat    [--algo ecdsa-p256|ecdsa-p384] [--keep]\n"
"               Chạy bộ Correctness + Negative test tự động (PASS/FAIL per case + summary).\n";
}

static ecdsa::SigEncoding parse_enc(const std::string& s) {
    return s.empty() ? ecdsa::SigEncoding::DER : ecdsa::sigenc_from_string(s);
}

// ── helpers cho bench ────────────────────────────────────────────────────
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
    auto curve = ecdsa::curve_from_string(a.get("--algo", "ecdsa-p256"));
    auto fmt   = ecdsa::keyformat_from_string(a.get("--format", "pem"));
    auto priv  = a.get("--priv"), pub = a.get("--pub");
    if (priv.empty() || pub.empty()) { usage(); return 2; }
    ecdsa::keygen(curve, priv, pub, fmt);
    std::cout << "[OK] ECDSA " << ecdsa::curve_to_string(curve)
              << " keypair → " << priv << ", " << pub << "\n";
    return 0;
}

static int cmd_sign(const Args& a) {
    auto priv = a.get("--priv"), in = a.get("--in"), out = a.get("--out");
    if (priv.empty() || in.empty() || out.empty()) { usage(); return 2; }
    auto enc  = parse_enc(a.get("--encode", "der"));
    auto hash = a.get("--hash", "");
    auto msg  = ecdsa::read_file(in);
    auto sig  = ecdsa::sign_bytes(priv, msg, hash, enc);
    ecdsa::write_file(out, sig);
    if (enc == ecdsa::SigEncoding::Base64) {
        std::string s(sig.begin(), sig.end());
        std::cout << "[OK] signature (base64): " << s << "\n";
    } else {
        std::cout << "[OK] signature (hex): " << ecdsa::hex_encode(sig) << "\n";
    }
    return 0;
}

static int cmd_verify(const Args& a) {
    auto pub = a.get("--pub"), in = a.get("--in"), sigp = a.get("--sig");
    if (pub.empty() || in.empty() || sigp.empty()) { usage(); return 2; }
    auto enc  = parse_enc(a.get("--encode", "der"));
    auto hash = a.get("--hash", "");
    auto msg  = ecdsa::read_file(in);
    auto sig  = ecdsa::read_file(sigp);
    bool ok = ecdsa::verify_bytes(pub, msg, sig, hash, enc);
    std::cout << (ok ? "[OK] Signature valid\n" : "[FAIL] Signature INVALID\n");
    return ok ? 0 : 1;
}

static int cmd_batch(const Args& a) {
    auto pub = a.get("--pub"), dir = a.get("--dir");
    if (pub.empty() || dir.empty()) { usage(); return 2; }
    auto enc  = parse_enc(a.get("--encode", "der"));
    auto hash = a.get("--hash", "");
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
        auto msg = ecdsa::read_file(msg_path);
        auto sig = ecdsa::read_file(p.string());
        bool good = ecdsa::verify_bytes(pub, msg, sig, hash, enc);
        std::cout << (good ? "PASS  " : "FAIL  ") << p.filename().string() << "\n";
        if (good) ++ok;
    }
    std::cout << "Summary: " << ok << "/" << total << " passed\n";
    return (ok == total) ? 0 : 1;
}

// ── bench ────────────────────────────────────────────────────────────────
static int cmd_bench(const Args& a) {
    std::string op = a.get("--op");
    if (op.empty()) { usage(); return 2; }
    auto curve = ecdsa::curve_from_string(a.get("--algo", "ecdsa-p256"));
    int N = a.get_int("--n", 30);
    int B = a.get_int("--block", 1000);
    int size = a.get_int("--size", 1024);
    std::string logp = a.get("--log", "");
    std::string hash = a.get("--hash", "");

    // Tạo dataset tạm (key + message) — KHÔNG ghi đè key của user.
    std::string tdir = (fs::temp_directory_path() / "lab5_bench_ecdsa").string();
    fs::create_directories(tdir);
    std::string priv = tdir + "/bench_priv.pem";
    std::string pub  = tdir + "/bench_pub.pem";
    Bytes msg(size); for (int i = 0; i < size; ++i) msg[i] = (uint8_t)(i & 0xFF);

    if (op != "keygen") {
        ecdsa::keygen(curve, priv, pub, ecdsa::KeyFormat::PEM);
    }
    Bytes precomputed_sig;
    if (op == "verify") {
        precomputed_sig = ecdsa::sign_bytes(priv, msg, hash, ecdsa::SigEncoding::DER);
    }

    auto do_one = [&]() {
        if (op == "keygen")      ecdsa::keygen(curve, priv, pub, ecdsa::KeyFormat::PEM);
        else if (op == "sign")   (void)ecdsa::sign_bytes(priv, msg, hash, ecdsa::SigEncoding::DER);
        else if (op == "verify") (void)ecdsa::verify_bytes(pub, msg, precomputed_sig, hash, ecdsa::SigEncoding::DER);
        else throw std::runtime_error("Unknown --op (keygen|sign|verify)");
    };

    // Warm-up 1 giây
    using clk = std::chrono::steady_clock;
    auto t_warm = clk::now();
    while (std::chrono::duration<double>(clk::now() - t_warm).count() < 1.0) do_one();

    std::vector<double> per_op_us; per_op_us.reserve(N);
    for (int r = 0; r < N; ++r) {
        auto t0 = clk::now();
        for (int i = 0; i < B; ++i) do_one();
        auto t1 = clk::now();
        double us = std::chrono::duration<double, std::micro>(t1 - t0).count() / B;
        per_op_us.push_back(us);
    }
    auto s = compute_stat(per_op_us);

    std::cout << "ECDSA bench  op=" << op
              << "  algo=" << ecdsa::curve_to_string(curve)
              << "  N=" << N << "  block=" << B
              << "  msg=" << size << "B\n"
              << "  mean   = " << s.mean   << " µs/op\n"
              << "  median = " << s.median << " µs/op\n"
              << "  stddev = " << s.sd     << " µs\n"
              << "  95% CI = [" << s.ci95_lo << ", " << s.ci95_hi << "] µs\n"
              << "  throughput ≈ " << (1e6 / s.mean) << " ops/s\n";

    if (!logp.empty()) {
        if (auto pp = fs::path(logp).parent_path(); !pp.empty()) fs::create_directories(pp);
        std::ofstream f(logp);
        f << "op,algo,N,block,msg_size,round,us_per_op\n";
        for (int r = 0; r < N; ++r)
            f << op << "," << ecdsa::curve_to_string(curve) << "," << N << "," << B << ","
              << size << "," << r << "," << per_op_us[r] << "\n";
        f << "# summary,mean," << s.mean << ",median," << s.median
          << ",sd," << s.sd << ",ci95_lo," << s.ci95_lo << ",ci95_hi," << s.ci95_hi << "\n";
        std::cout << "  log → " << logp << "\n";
    }
    return 0;
}

// ── KAT / Negative tests (theo spec Lab 5 §3) ────────────────────────────
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
    std::string algo = a.get("--algo", "ecdsa-p256");
    auto curve = ecdsa::curve_from_string(algo);
    bool keep  = a.has("--keep");

    std::string tdir = (fs::temp_directory_path() / "lab5_kat_ecdsa").string();
    fs::create_directories(tdir);
    auto P = [&](const char* n){ return tdir + "/" + n; };

    std::cout << "ECDSA KAT — algo=" << algo << "  workdir=" << tdir << "\n";

    // Sinh 2 cặp khoá (A, B) + 2 message khác nhau.
    ecdsa::keygen(curve, P("A_priv.pem"), P("A_pub.pem"), ecdsa::KeyFormat::PEM);
    ecdsa::keygen(curve, P("B_priv.pem"), P("B_pub.pem"), ecdsa::KeyFormat::PEM);
    Bytes msg1 = {'H','e','l','l','o',' ','L','a','b','5'};
    Bytes msg2 = {'O','t','h','e','r',' ','m','s','g'};
    ecdsa::write_file(P("msg1.bin"), msg1);
    ecdsa::write_file(P("msg2.bin"), msg2);

    std::vector<CaseResult> R;

    // 1. Positive roundtrip qua cả 3 encoding.
    for (auto enc : {ecdsa::SigEncoding::DER, ecdsa::SigEncoding::Raw, ecdsa::SigEncoding::Base64}) {
        std::string ename = (enc == ecdsa::SigEncoding::DER ? "der"
                            : enc == ecdsa::SigEncoding::Raw ? "raw" : "base64");
        run_case(R, "positive roundtrip encode=" + ename, [&]{
            auto sig = ecdsa::sign_bytes(P("A_priv.pem"), msg1, "", enc);
            return ecdsa::verify_bytes(P("A_pub.pem"), msg1, sig, "", enc);
        });
    }

    // Chuẩn bị 1 chữ ký DER cố định cho các bài tampering.
    auto sig_der = ecdsa::sign_bytes(P("A_priv.pem"), msg1, "", ecdsa::SigEncoding::DER);

    // 2. Modified message → FAIL.
    run_case(R, "modified message rejected", [&]{
        return !ecdsa::verify_bytes(P("A_pub.pem"), msg2, sig_der, "", ecdsa::SigEncoding::DER);
    });

    // 3. Modified signature (lật 1 bit ở giữa) → FAIL.
    run_case(R, "modified signature rejected", [&]{
        Bytes bad = sig_der;
        if (bad.size() > 8) bad[bad.size()/2] ^= 0x01;
        return !ecdsa::verify_bytes(P("A_pub.pem"), msg1, bad, "", ecdsa::SigEncoding::DER);
    });

    // 4. Wrong public key (B) → FAIL.
    run_case(R, "wrong public key rejected", [&]{
        return !ecdsa::verify_bytes(P("B_pub.pem"), msg1, sig_der, "", ecdsa::SigEncoding::DER);
    });

    // 5. Wrong hash function → FAIL (sign sha256, verify sha384 — chỉ áp dụng cho P-256
    //    vì P-384 mặc định là sha384; với P-384 ta đảo lại).
    run_case(R, "wrong hash function rejected", [&]{
        std::string sign_h = (curve == ecdsa::Curve::P256) ? "sha256" : "sha384";
        std::string ver_h  = (curve == ecdsa::Curve::P256) ? "sha384" : "sha256";
        auto sig = ecdsa::sign_bytes(P("A_priv.pem"), msg1, sign_h, ecdsa::SigEncoding::DER);
        return !ecdsa::verify_bytes(P("A_pub.pem"), msg1, sig, ver_h, ecdsa::SigEncoding::DER);
    });

    // 6. Encoding mismatch: ký DER, verify như raw → FAIL closed.
    run_case(R, "encoding mismatch rejected", [&]{
        return !ecdsa::verify_bytes(P("A_pub.pem"), msg1, sig_der, "", ecdsa::SigEncoding::Raw);
    });

    // 7. Malformed key file → throw exception (sign_bytes phải fail).
    {
        std::string bad_key = P("bad_priv.pem");
        ecdsa::write_file(bad_key, std::string("not a real key"));
        run_case(R, "malformed key file rejected (sign)", [&]{
            try { (void)ecdsa::sign_bytes(bad_key, msg1, "", ecdsa::SigEncoding::DER); return false; }
            catch (const std::exception&) { return true; }
        });
    }

    // 8. Truncated signature → FAIL.
    run_case(R, "truncated signature rejected", [&]{
        Bytes trunc(sig_der.begin(), sig_der.begin() + sig_der.size()/2);
        return !ecdsa::verify_bytes(P("A_pub.pem"), msg1, trunc, "", ecdsa::SigEncoding::DER);
    });

    // 9. Wrong algorithm identifier (cross-curve) → FAIL.
    //    Spec §3 mandate: chữ ký từ curve này phải fail khi verify bằng public key
    //    của curve khác.
    run_case(R, "wrong algorithm identifier (cross-curve) rejected", [&]{
        auto other = (curve == ecdsa::Curve::P256) ? ecdsa::Curve::P384 : ecdsa::Curve::P256;
        ecdsa::keygen(other, P("C_priv.pem"), P("C_pub.pem"), ecdsa::KeyFormat::PEM);
        return !ecdsa::verify_bytes(P("C_pub.pem"), msg1, sig_der, "", ecdsa::SigEncoding::DER);
    });

    int ok = 0; for (auto& r : R) if (r.pass) ++ok;
    std::cout << "Summary: " << ok << "/" << R.size() << " cases passed\n";
    if (!keep) {
        std::error_code ec; fs::remove_all(tdir, ec);
    } else {
        std::cout << "  (--keep) artifacts left at " << tdir << "\n";
    }
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
