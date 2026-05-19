#include "aes_core.h"
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/xts.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace std;
using namespace CryptoPP;

// Helpers
string hex_decode(string encoded) {
    string decoded;
    StringSource(encoded, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

string ReadFile(const char* path) {
    string data;
    FileSource(path, true, new StringSink(data));
    return data;
}

void WriteFile(const char* path, const string& data) {
    StringSource(data, true, new FileSink(path));
}

// CCM Dispatcher
template <int T_Size>
string Run_CCM_Encrypt(const CryptoPP::byte* key, size_t keyLen, const CryptoPP::byte* iv, size_t ivLen,
                      const string& aad, const string& plaintext) {
    typename CCM<AES, T_Size>::Encryption enc;
    enc.SetKeyWithIV(key, keyLen, iv, ivLen);
    enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);
    string cipher;
    AuthenticatedEncryptionFilter ef(enc, new StringSink(cipher));
    if (!aad.empty()) {
        ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        ef.ChannelMessageEnd(AAD_CHANNEL);
    }
    ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
    return cipher;
}

template <int T_Size>
string Run_CCM_Decrypt(const string& cipher, const CryptoPP::byte* key, size_t keyLen,
                      const CryptoPP::byte* iv, size_t ivLen, const string& aad) {
    typename CCM<AES, T_Size>::Decryption dec;
    dec.SetKeyWithIV(key, keyLen, iv, ivLen);
    dec.SpecifyDataLengths(aad.size(), cipher.size() - T_Size, 0);
    string recovered;
    AuthenticatedDecryptionFilter df(dec, new StringSink(recovered), 
        AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION);
    if (!aad.empty()) {
        df.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        df.ChannelMessageEnd(AAD_CHANNEL);
    }
    df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)cipher.data(), cipher.size());
    df.ChannelMessageEnd(DEFAULT_CHANNEL);
    return recovered;
}

extern "C" {

AES_API void GenerateKeyAndIV(const char* mode, int keySize, const char* format, const char* keyFile, const char* ivFile) {
    AutoSeededRandomPool prng;
    SecByteBlock key(keySize), iv(16);
    prng.GenerateBlock(key, key.size());
    if (string(mode) != "ECB") prng.GenerateBlock(iv, iv.size());

    string kStr, iStr;
    if (string(format) == "Hex") {
        StringSource(key.data(), key.size(), true, new HexEncoder(new StringSink(kStr)));
        if (string(mode) != "ECB") StringSource(iv.data(), iv.size(), true, new HexEncoder(new StringSink(iStr)));
    } else {
        kStr.assign((const char*)key.data(), key.size());
        iStr.assign((const char*)iv.data(), iv.size());
    }
    WriteFile(keyFile, kStr);
    if (string(mode) != "ECB") WriteFile(ivFile, iStr);
}

AES_API int AES_Process(const char* action, const char* mode, const char* key_hex, const char* iv_hex,
                        const char* input_path, const char* output_path, const char* aad_hex, int tag_size) {
    try {
        string strAction(action);
        string strMode(mode);
        string key = hex_decode(key_hex);
        string iv = (strMode != "ECB") ? hex_decode(iv_hex) : "";
        string aad = (aad_hex && strlen(aad_hex) > 0) ? hex_decode(aad_hex) : "";
        
        if (strAction == "encrypt") {
            string plain = ReadFile(input_path);
            string cipher;
            if (strMode == "ECB") {
                ECB_Mode<AES>::Encryption e;
                e.SetKey((const CryptoPP::byte*)key.data(), key.size());
                StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
            } else if (strMode == "CBC") {
                CBC_Mode<AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
            } else if (strMode == "CFB") {
                CFB_Mode<AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
            } else if (strMode == "OFB") {
                OFB_Mode<AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
            } else if (strMode == "CTR") {
                CTR_Mode<AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
            } else if (strMode == "XTS") {
                XTS<AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
            } else if (strMode == "GCM") {
                GCM<AES>::Encryption e;
                e.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size());
                AuthenticatedEncryptionFilter ef(e, new StringSink(cipher));
                if (!aad.empty()) {
                    ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
                    ef.ChannelMessageEnd(AAD_CHANNEL);
                }
                ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)plain.data(), plain.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);
            } else if (strMode == "CCM") {
                if (tag_size == 16) cipher = Run_CCM_Encrypt<16>((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size(), aad, plain);
                else if (tag_size == 12) cipher = Run_CCM_Encrypt<12>((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size(), aad, plain);
                else cipher = Run_CCM_Encrypt<8>((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size(), aad, plain);
            }
            WriteFile(output_path, cipher);
        } else {
            string cipher = ReadFile(input_path);
            string recovered;
            if (strMode == "ECB") {
                ECB_Mode<AES>::Decryption d;
                d.SetKey((const CryptoPP::byte*)key.data(), key.size());
                StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
            } else if (strMode == "CBC") {
                CBC_Mode<AES>::Decryption d;
                d.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
            } else if (strMode == "CFB") {
                CFB_Mode<AES>::Decryption d;
                d.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
            } else if (strMode == "OFB") {
                OFB_Mode<AES>::Decryption d;
                d.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
            } else if (strMode == "CTR") {
                CTR_Mode<AES>::Decryption d;
                d.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
            } else if (strMode == "XTS") {
                XTS<AES>::Decryption d;
                d.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data());
                StringSource(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING));
            } else if (strMode == "GCM") {
                GCM<AES>::Decryption d;
                d.SetKeyWithIV((const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size());
                AuthenticatedDecryptionFilter df(d, new StringSink(recovered));
                if (!aad.empty()) {
                    df.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
                    df.ChannelMessageEnd(AAD_CHANNEL);
                }
                df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)cipher.data(), cipher.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);
            } else if (strMode == "CCM") {
                if (tag_size == 16) recovered = Run_CCM_Decrypt<16>(cipher, (const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size(), aad);
                else if (tag_size == 12) recovered = Run_CCM_Decrypt<12>(cipher, (const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size(), aad);
                else recovered = Run_CCM_Decrypt<8>(cipher, (const CryptoPP::byte*)key.data(), key.size(), (const CryptoPP::byte*)iv.data(), iv.size(), aad);
            }
            WriteFile(output_path, recovered);
        }
        return 0;
    } catch (...) { return -1; }
}

} // extern "C"