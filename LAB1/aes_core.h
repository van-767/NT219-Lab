// aes_core.h
#pragma once

#ifdef _WIN32
    #ifdef AES_CORE_EXPORTS
        #define AES_API __declspec(dllexport)
    #else
        #define AES_API __declspec(dllimport)
    #endif
#else
    #define AES_API __attribute__((visibility("default")))
#endif

extern "C" {
    AES_API void GenerateKeyAndIV(const char* mode, int keySize, const char* format, const char* keyFile, const char* ivFile);
    
    // Unified process function for GUI
    AES_API int AES_Process(const char* action, const char* mode, const char* key_hex, const char* iv_hex,
                            const char* input_path, const char* output_path, const char* aad_hex, int tag_size);
}