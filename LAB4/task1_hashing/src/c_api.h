#pragma once
// Flat C ABI cho GUI (PySide6 ctypes / C# P/Invoke).

#ifdef _WIN32
  #ifdef HASH_LAB_BUILD_DLL
    #define HASH_LAB_API __declspec(dllexport)
  #else
    #define HASH_LAB_API __declspec(dllimport)
  #endif
#else
  #define HASH_LAB_API __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

HASH_LAB_API const char* hash_last_error(void);

// Hash text and return hex digest through a caller-provided buffer.
// algo: "sha256", "sha3-256", "shake128", ...
// outlen: used only for SHAKE (XOF). Ignored for fixed-output hashes.
// out_hex: buffer >= outlen*2 + 1 bytes (NUL-terminated).
// Returns 0 on success, non-zero on error.
HASH_LAB_API int hash_text(const char* algo, const char* text, int text_len,
                           int outlen, char* out_hex, int out_hex_size);

// Hash file streamed.
HASH_LAB_API int hash_file(const char* algo, const char* file_path,
                           int outlen, char* out_hex, int out_hex_size);

// Run KAT and return pass/fail counts through output parameters.
HASH_LAB_API int hash_run_kat(const char* json_path, int* out_passed, int* out_failed);

// Benchmark a single case. Output per-operation stats in microseconds.
HASH_LAB_API int hash_bench(const char* algo, int size_bytes, int n_blocks, int block_size,
                            int outlen,
                            double* mean, double* median, double* sd,
                            double* ci_lo, double* ci_hi, double* throughput_MiBps);

#ifdef __cplusplus
}
#endif
