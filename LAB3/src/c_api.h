#pragma once
// Flat C ABI for FFI consumers (PySide6 via ctypes, C# via P/Invoke).
// All strings are UTF-8, null-terminated. All functions return 0 on success,
// non-zero on failure; call rsa_last_error() for a human-readable message.

#ifdef _WIN32
  #ifdef RSA_LAB_BUILD_DLL
    #define RSA_LAB_API __declspec(dllexport)
  #else
    #define RSA_LAB_API __declspec(dllimport)
  #endif
#else
  #define RSA_LAB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

RSA_LAB_API const char* rsa_last_error(void);

RSA_LAB_API int rsa_keygen(int bits,
                           const char* priv_pem_path,
                           const char* pub_pem_path);

RSA_LAB_API int rsa_encrypt(const char* pub_pem_path,
                            const char* in_path,
                            const char* out_path,
                            const char* label /* may be empty string */);

RSA_LAB_API int rsa_decrypt(const char* priv_pem_path,
                            const char* in_path,
                            const char* out_path,
                            const char* label);

// Returns 0 if every test passed; writes counts via out params.
RSA_LAB_API int rsa_run_kat(const char* kat_json_path,
                            int* out_passed, int* out_failed);

// Benchmarks. Outputs are populated on success.
RSA_LAB_API int rsa_bench_keygen(int bits, int n,
                                 double* mean, double* median,
                                 double* stddev, double* ci_lo, double* ci_hi);

RSA_LAB_API int rsa_bench_oaep_enc(int bits, int n,
                                   double* mean, double* median,
                                   double* stddev, double* ci_lo, double* ci_hi);

RSA_LAB_API int rsa_bench_oaep_dec(int bits, int n,
                                   double* mean, double* median,
                                   double* stddev, double* ci_lo, double* ci_hi);

RSA_LAB_API int rsa_bench_aes_gcm(int n, unsigned long long msg_size,
                                  double* mean, double* median,
                                  double* stddev, double* ci_lo, double* ci_hi);

#ifdef __cplusplus
}
#endif
