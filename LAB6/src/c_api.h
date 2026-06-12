#pragma once
// Flat C ABI cho Python (ctypes) và C# (P/Invoke).
// String UTF-8 null-terminated. Trả 0 = OK, khác 0 = lỗi (gọi pq_last_error()).

#ifdef _WIN32
  #ifdef PQ_LAB_BUILD_DLL
    #define PQ_LAB_API __declspec(dllexport)
  #else
    #define PQ_LAB_API __declspec(dllimport)
  #endif
#else
  #define PQ_LAB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

PQ_LAB_API const char* pq_last_error(void);

// ML-DSA
PQ_LAB_API int pq_mldsa_keygen(const char* algo, const char* priv_path, const char* pub_path);
PQ_LAB_API int pq_mldsa_sign  (const char* priv_path, const char* in_path, const char* sig_path);
PQ_LAB_API int pq_mldsa_verify(const char* pub_path,  const char* in_path, const char* sig_path);

// ML-KEM
PQ_LAB_API int pq_mlkem_keygen(const char* algo, const char* priv_path, const char* pub_path);
PQ_LAB_API int pq_mlkem_encaps(const char* pub_path,  const char* ct_path, const char* ss_path);
PQ_LAB_API int pq_mlkem_decaps(const char* priv_path, const char* ct_path, const char* ss_path);

// PQ Certificate
PQ_LAB_API int pq_cert_make(const char* algo,
                            const char* ca_priv_path,
                            const char* subj_pub_path,
                            const char* subject,
                            const char* cert_out_path);

PQ_LAB_API int pq_cert_verify(const char* ca_pub_path, const char* cert_path);

#ifdef __cplusplus
}
#endif
