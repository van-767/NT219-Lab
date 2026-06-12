// PQ_LAB_BUILD_DLL được CMake set qua target_compile_definitions.
#include "c_api.h"
#include "pq_core.h"

#include <mutex>
#include <string>
#include <sstream>
#include <fstream>

namespace {
std::mutex g_err_mu;
std::string g_err;
void set_err(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_err_mu);
    g_err = s;
}

std::string json_escape(const std::string& s) {
    std::string o; for (char c : s) {
        switch (c) { case '"': o += "\\\""; break; case '\\': o += "\\\\"; break;
                     case '\n': o += "\\n"; break; default: o += c; }
    }
    return o;
}
std::string json_get(const std::string& j, const std::string& key) {
    auto p = j.find("\"" + key + "\"");
    if (p == std::string::npos) throw std::runtime_error("cert missing field: " + key);
    p = j.find(':', p); p = j.find('"', p);
    auto e = j.find('"', p + 1);
    return j.substr(p + 1, e - p - 1);
}
} // anon

#define GUARD_BEGIN try {
#define GUARD_END(ret) } catch (const std::exception& e) { set_err(e.what()); return (ret); } \
                        catch (...) { set_err("unknown error"); return (ret); }

extern "C" {

const char* pq_last_error(void) {
    std::lock_guard<std::mutex> lk(g_err_mu);
    return g_err.c_str();
}

// ---- ML-DSA --------------------------------------------------------
int pq_mldsa_keygen(const char* algo, const char* priv, const char* pub) {
    GUARD_BEGIN
    pq::mldsa_keygen(pq::dsa_from_string(algo ? algo : "mldsa-44"),
                     priv ? priv : "", pub ? pub : "");
    set_err(""); return 0;
    GUARD_END(1)
}
int pq_mldsa_sign(const char* priv, const char* in_, const char* sig_out) {
    GUARD_BEGIN
    auto msg = pq::read_file(in_ ? in_ : "");
    auto sig = pq::mldsa_sign(priv ? priv : "", msg);
    pq::write_file(sig_out ? sig_out : "", sig);
    set_err(""); return 0;
    GUARD_END(1)
}
int pq_mldsa_verify(const char* pub, const char* in_, const char* sig_) {
    GUARD_BEGIN
    auto msg = pq::read_file(in_ ? in_ : "");
    auto sig = pq::read_file(sig_ ? sig_ : "");
    bool ok = pq::mldsa_verify(pub ? pub : "", msg, sig);
    set_err(ok ? "" : "verify failed");
    return ok ? 0 : 1;
    GUARD_END(1)
}

// ---- ML-KEM --------------------------------------------------------
int pq_mlkem_keygen(const char* algo, const char* priv, const char* pub) {
    GUARD_BEGIN
    pq::mlkem_keygen(pq::kem_from_string(algo ? algo : "mlkem-512"),
                     priv ? priv : "", pub ? pub : "");
    set_err(""); return 0;
    GUARD_END(1)
}
int pq_mlkem_encaps(const char* pub, const char* ct, const char* ss) {
    GUARD_BEGIN
    pq::mlkem_encaps(pub ? pub : "", ct ? ct : "", ss ? ss : "");
    set_err(""); return 0;
    GUARD_END(1)
}
int pq_mlkem_decaps(const char* priv, const char* ct, const char* ss) {
    GUARD_BEGIN
    pq::mlkem_decaps(priv ? priv : "", ct ? ct : "", ss ? ss : "");
    set_err(""); return 0;
    GUARD_END(1)
}

// ---- PQ Certificate ------------------------------------------------
int pq_cert_make(const char* algo_c, const char* ca_priv, const char* subj_pub,
                 const char* subject_c, const char* out_path) {
    GUARD_BEGIN
    std::string algo = algo_c ? algo_c : "mldsa-44";
    std::string subject = subject_c ? subject_c : "";
    auto p = pq::dsa_from_string(algo);
    auto pub_pem_bytes = pq::read_file(subj_pub ? subj_pub : "");
    std::string pub_pem(pub_pem_bytes.begin(), pub_pem_bytes.end());
    std::string lbl = (p == pq::DsaParam::ML_DSA_44 ? "ML-DSA-44 PUBLIC KEY"
                      : p == pq::DsaParam::ML_DSA_65 ? "ML-DSA-65 PUBLIC KEY"
                      : "ML-DSA-87 PUBLIC KEY");
    auto subj_raw = pq::pem_unwrap(lbl, pub_pem);

    // Build TBS = subject || raw_pubkey
    pq::Bytes tbs;
    tbs.insert(tbs.end(), subject.begin(), subject.end());
    tbs.insert(tbs.end(), subj_raw.begin(), subj_raw.end());

    auto ca_sig = pq::mldsa_sign(ca_priv ? ca_priv : "", tbs);

    std::ostringstream cert;
    cert << "{\n"
         << "  \"subject\": \""    << json_escape(subject)        << "\",\n"
         << "  \"algorithm\": \""  << pq::dsa_name(p)             << "\",\n"
         << "  \"public_key\": \"" << pq::b64_encode(subj_raw)    << "\",\n"
         << "  \"issuer\": \"PQ-CA\",\n"
         << "  \"signature\": \""  << pq::b64_encode(ca_sig)      << "\"\n"
         << "}\n";
    pq::write_file(out_path ? out_path : "", cert.str());
    set_err(""); return 0;
    GUARD_END(1)
}

int pq_cert_verify(const char* ca_pub, const char* cert_path) {
    GUARD_BEGIN
    auto cert_bytes = pq::read_file(cert_path ? cert_path : "");
    std::string cert(cert_bytes.begin(), cert_bytes.end());
    std::string subject = json_get(cert, "subject");
    auto pubraw = pq::b64_decode(json_get(cert, "public_key"));
    auto sig    = pq::b64_decode(json_get(cert, "signature"));

    pq::Bytes tbs;
    tbs.insert(tbs.end(), subject.begin(), subject.end());
    tbs.insert(tbs.end(), pubraw.begin(), pubraw.end());

    bool ok = pq::mldsa_verify(ca_pub ? ca_pub : "", tbs, sig);
    set_err(ok ? "" : "cert signature verify failed");
    return ok ? 0 : 1;
    GUARD_END(1)
}

} // extern "C"
