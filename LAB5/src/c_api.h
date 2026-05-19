// Lab 5 — C ABI cho GUI Python (ctypes). Mọi hàm trả 0 = OK, khác 0 = lỗi;
// chi tiết lỗi cuối lấy qua sig_last_error().
#pragma once
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32)
  #if defined(SIG_BUILDING_DLL)
    #define SIG_API __declspec(dllexport)
  #else
    #define SIG_API __declspec(dllimport)
  #endif
#else
  #define SIG_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

SIG_API const char* sig_last_error(void);

// ── ECDSA ────────────────────────────────────────────────────────────────
// algo: "ecdsa-p256" | "ecdsa-p384". fmt: "pem" | "der".
SIG_API int sig_ecdsa_keygen(const char* algo, const char* priv_path,
                             const char* pub_path, const char* fmt);

// enc: "raw" | "der" | "base64". hash: "" (mặc định theo curve) | "sha256" | "sha384".
// Trả về độ dài chữ ký qua *out_sig_len; ghi vào file out_path. Trả 0 = OK.
SIG_API int sig_ecdsa_sign(const char* priv_path, const char* in_path,
                           const char* out_path, const char* hash,
                           const char* enc, size_t* out_sig_len);

// Trả 0 = hợp lệ; 1 = invalid; <0 = lỗi parse.
SIG_API int sig_ecdsa_verify(const char* pub_path, const char* in_path,
                             const char* sig_path, const char* hash,
                             const char* enc);

// ── RSA-PSS ──────────────────────────────────────────────────────────────
SIG_API int sig_rsapss_keygen(int bits, const char* priv_path,
                              const char* pub_path, const char* fmt);

SIG_API int sig_rsapss_sign(const char* priv_path, const char* in_path,
                            const char* out_path, const char* hash,
                            int salt_len, const char* enc, size_t* out_sig_len);

SIG_API int sig_rsapss_verify(const char* pub_path, const char* in_path,
                              const char* sig_path, const char* hash,
                              int salt_len, const char* enc);

#ifdef __cplusplus
}
#endif
