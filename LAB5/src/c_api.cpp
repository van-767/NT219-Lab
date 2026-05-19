#define SIG_BUILDING_DLL
#include "c_api.h"
#include "ecdsa_core.h"
#include "rsapss_core.h"

#include <string>
#include <mutex>

// thread-local last error
static thread_local std::string g_last_err;
static void set_err(const char* s) { g_last_err = s ? s : ""; }
static void clear_err() { g_last_err.clear(); }
static void need(const char* p, const char* name) {
    if (!p || !*p) throw std::runtime_error(std::string("missing required: ") + name);
}

extern "C" {

const char* sig_last_error(void) { return g_last_err.c_str(); }

// ── ECDSA ────────────────────────────────────────────────────────────────
int sig_ecdsa_keygen(const char* algo, const char* priv_path,
                     const char* pub_path, const char* fmt) {
    try {
        clear_err();
        need(priv_path, "priv_path"); need(pub_path, "pub_path");
        auto c = ecdsa::curve_from_string(algo ? algo : "ecdsa-p256");
        auto f = ecdsa::keyformat_from_string(fmt && *fmt ? fmt : "pem");
        ecdsa::keygen(c, priv_path, pub_path, f);
        return 0;
    } catch (const std::exception& e) { set_err(e.what()); return -1; }
}

int sig_ecdsa_sign(const char* priv_path, const char* in_path,
                   const char* out_path, const char* hash,
                   const char* enc, size_t* out_sig_len) {
    try {
        clear_err();
        need(priv_path, "priv_path"); need(in_path, "in_path"); need(out_path, "out_path");
        auto msg = ecdsa::read_file(in_path);
        auto e   = ecdsa::sigenc_from_string(enc && *enc ? enc : "der");
        auto sig = ecdsa::sign_bytes(priv_path, msg, hash ? hash : "", e);
        ecdsa::write_file(out_path, sig);
        if (out_sig_len) *out_sig_len = sig.size();
        return 0;
    } catch (const std::exception& e) { set_err(e.what()); return -1; }
}

int sig_ecdsa_verify(const char* pub_path, const char* in_path,
                     const char* sig_path, const char* hash,
                     const char* enc) {
    try {
        clear_err();
        need(pub_path, "pub_path"); need(in_path, "in_path"); need(sig_path, "sig_path");
        auto msg = ecdsa::read_file(in_path);
        auto sg  = ecdsa::read_file(sig_path);
        auto e   = ecdsa::sigenc_from_string(enc && *enc ? enc : "der");
        bool ok  = ecdsa::verify_bytes(pub_path, msg, sg, hash ? hash : "", e);
        return ok ? 0 : 1;
    } catch (const std::exception& e) { set_err(e.what()); return -1; }
}

// ── RSA-PSS ──────────────────────────────────────────────────────────────
int sig_rsapss_keygen(int bits, const char* priv_path,
                      const char* pub_path, const char* fmt) {
    try {
        clear_err();
        need(priv_path, "priv_path"); need(pub_path, "pub_path");
        auto f = rsapss::keyformat_from_string(fmt && *fmt ? fmt : "pem");
        rsapss::keygen(bits, priv_path, pub_path, f);
        return 0;
    } catch (const std::exception& e) { set_err(e.what()); return -1; }
}

int sig_rsapss_sign(const char* priv_path, const char* in_path,
                    const char* out_path, const char* hash,
                    int salt_len, const char* enc, size_t* out_sig_len) {
    try {
        clear_err();
        need(priv_path, "priv_path"); need(in_path, "in_path"); need(out_path, "out_path");
        auto msg = rsapss::read_file(in_path);
        auto e   = rsapss::sigenc_from_string(enc && *enc ? enc : "raw");
        auto sig = rsapss::sign_bytes(priv_path, msg, hash ? hash : "sha256", salt_len, e);
        rsapss::write_file(out_path, sig);
        if (out_sig_len) *out_sig_len = sig.size();
        return 0;
    } catch (const std::exception& e) { set_err(e.what()); return -1; }
}

int sig_rsapss_verify(const char* pub_path, const char* in_path,
                      const char* sig_path, const char* hash,
                      int salt_len, const char* enc) {
    try {
        clear_err();
        need(pub_path, "pub_path"); need(in_path, "in_path"); need(sig_path, "sig_path");
        auto msg = rsapss::read_file(in_path);
        auto sg  = rsapss::read_file(sig_path);
        auto e   = rsapss::sigenc_from_string(enc && *enc ? enc : "raw");
        bool ok  = rsapss::verify_bytes(pub_path, msg, sg, hash ? hash : "sha256", salt_len, e);
        return ok ? 0 : 1;
    } catch (const std::exception& e) { set_err(e.what()); return -1; }
}

} // extern "C"
