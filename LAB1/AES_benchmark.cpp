
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;
#include <iostream>
#include <string>
#include <cstdlib>
#include <chrono>
#include <iomanip>
#include <vector>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/gcm.h>
#include <cryptopp/xts.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>

using namespace std;
using namespace CryptoPP;

// --- helpers for encoding/decoding ---
string base64encode(const CryptoPP::byte *data, size_t size)
{
    string encoded;
    StringSource(data, size, true, new Base64Encoder(new StringSink(encoded), false));
    return encoded;
}
string base64decode(const string &encoded)
{
    string decoded;
    StringSource(encoded, true, new Base64Decoder(new StringSink(decoded)));
    return decoded;
}
string hexencode(const CryptoPP::byte *data, size_t size)
{
    string encoded;
    StringSource(data, size, true, new HexEncoder(new StringSink(encoded), false));
    return encoded;
}
string hexdecode(const string &encoded)
{
    string decoded;
    StringSource(encoded, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

// Read file entirely into string
string ReadFileToString(const char *filename)
{
    string out;
    FileSource fs(filename, true, new StringSink(out));
    return out;
}

// Write string to file (binary/text)
void WriteStringToFile(const string &data, const char *filename)
{
    StringSource ss(data, true, new FileSink(filename));
}

// CCM Dispatcher for flexible tag sizes
template <int T_Size>
string Run_CCM_Encrypt(const CryptoPP::byte* key, size_t keyLen, const CryptoPP::byte* iv, size_t ivLen,
                      const string& aad, const string& plaintext)
{
    typename CCM<AES, T_Size>::Encryption enc;
    enc.SetKeyWithIV(key, keyLen, iv, ivLen);
    enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);

    string ciphertext;
    AuthenticatedEncryptionFilter ef(enc, new StringSink(ciphertext));

    if (!aad.empty()) {
        ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        ef.ChannelMessageEnd(AAD_CHANNEL);
    }

    ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    return ciphertext;
}
// CCM decrypt
template <int T_Size>
string Run_CCM_Decrypt(const string& ciphertext, const CryptoPP::byte* key, size_t keyLen,
                      const CryptoPP::byte* iv, size_t ivLen, const string& aad)
{
    typename CCM<AES, T_Size>::Decryption dec;
    dec.SetKeyWithIV(key, keyLen, iv, ivLen);

    size_t ctLen = ciphertext.size();
    if (ctLen < (size_t)T_Size) throw runtime_error("Ciphertext too short for tag");
    size_t msgLen = ctLen - T_Size;
    dec.SpecifyDataLengths(aad.size(), msgLen, 0);

    string plaintext;
    AuthenticatedDecryptionFilter df(
        dec,
        new StringSink(plaintext),
        AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION
    );

    if (!aad.empty()) {
        df.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
        df.ChannelMessageEnd(AAD_CHANNEL);
    }

    df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)ciphertext.data(), ciphertext.size());
    df.ChannelMessageEnd(DEFAULT_CHANNEL);

    return plaintext;
}
// CCM encrypt
string Dispatch_CCM_Encrypt(int tagLen, const CryptoPP::byte* k, size_t kl, const CryptoPP::byte* i, size_t il,
                           const string& a, const string& p)
{
    switch(tagLen) {
        case 4: return Run_CCM_Encrypt<4>(k, kl, i, il, a, p);
        case 6: return Run_CCM_Encrypt<6>(k, kl, i, il, a, p);
        case 8: return Run_CCM_Encrypt<8>(k, kl, i, il, a, p);
        case 10: return Run_CCM_Encrypt<10>(k, kl, i, il, a, p);
        case 12: return Run_CCM_Encrypt<12>(k, kl, i, il, a, p);
        case 14: return Run_CCM_Encrypt<14>(k, kl, i, il, a, p);
        case 16: return Run_CCM_Encrypt<16>(k, kl, i, il, a, p);
        default: throw runtime_error("Invalid Tag Length: " + to_string(tagLen));
    }
}
// CCM decrypt
string Dispatch_CCM_Decrypt(int tagLen, const string& ct, const CryptoPP::byte* k, size_t kl,
                           const CryptoPP::byte* i, size_t il, const string& a)
{
    switch(tagLen) {
        case 4: return Run_CCM_Decrypt<4>(ct, k, kl, i, il, a);
        case 6: return Run_CCM_Decrypt<6>(ct, k, kl, i, il, a);
        case 8: return Run_CCM_Decrypt<8>(ct, k, kl, i, il, a);
        case 10: return Run_CCM_Decrypt<10>(ct, k, kl, i, il, a);
        case 12: return Run_CCM_Decrypt<12>(ct, k, kl, i, il, a);
        case 14: return Run_CCM_Decrypt<14>(ct, k, kl, i, il, a);
        case 16: return Run_CCM_Decrypt<16>(ct, k, kl, i, il, a);
        default: throw runtime_error("Invalid Tag Length: " + to_string(tagLen));
    }
}
// AES encrypt
long long AESEncrypt(const char *mode, const char *keyIVFormat, const char *keyFile, const char *ivFile,
                     const char *cipherFormat,
                     const char *plainTextFile, const char *cipherTextFile,
                     int INNER_ROUNDS, const string& aad = "", int tagSize = 16)
{
    string dataKey = ReadFileToString(keyFile);
    string dataIV;
    string decodedKey, decodedIV;
    string strMode(mode);
    string strFormat(keyIVFormat);
    string strCFormat(cipherFormat);

    if (strMode != "ECB")
        dataIV = ReadFileToString(ivFile);

    if (strFormat == "Binary") {
        decodedKey = dataKey;
        decodedIV = dataIV;
    } else if (strFormat == "Hex") {
        decodedKey = hexdecode(dataKey);
        decodedIV = hexdecode(dataIV);
    } else if (strFormat == "Base64") {
        decodedKey = base64decode(dataKey);
        decodedIV = base64decode(dataIV);
    } else {
        cerr << "Invalid key/iv format\n";
        exit(1);
    }

    size_t keySize = decodedKey.size();
    size_t ivSize = decodedIV.size();
    if ((strMode == "CCM" || strMode == "GCM") && ivSize == 0)
        ivSize = 12;

    vector<CryptoPP::byte> keyVec(keySize);
    if (keySize > 0) memcpy(keyVec.data(), decodedKey.data(), keySize);

    vector<CryptoPP::byte> ivVec(ivSize);
    if (ivSize > 0) memcpy(ivVec.data(), decodedIV.data(), ivSize);

    string plain = ReadFileToString(plainTextFile);
    string cipher;

    long long total_inner_us = 0;

    for (int i = 0; i < INNER_ROUNDS; ++i)
    {
        auto t0 = chrono::high_resolution_clock::now();

        if (strMode == "ECB")
        {
            ECB_Mode<AES>::Encryption e;
            e.SetKey(keyVec.data(), (unsigned int)keySize);
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "CBC")
        {
            CBC_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "OFB")
        {
            OFB_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "CFB")
        {
            CFB_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "CTR")
        {
            CTR_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "XTS")
        {
            if (keySize != 32) { cerr << "XTS requires 32-byte key\n"; exit(1); }
            XTS<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            cipher.clear();
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
        }
        else if (strMode == "CCM")
        {
            cipher = Dispatch_CCM_Encrypt(tagSize, keyVec.data(), keySize, ivVec.data(), ivSize, aad, plain);
        }
        else if (strMode == "GCM")
        {
            GCM<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            cipher.clear();
            
            AuthenticatedEncryptionFilter ef(e, new StringSink(cipher));
            
            if (!aad.empty()) {
                ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
                ef.ChannelMessageEnd(AAD_CHANNEL);
            }
            
            ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)plain.data(), plain.size());
            ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        }
        else
        {
            cerr << "Unsupported mode\n";
            exit(1);
        }

        auto t1 = chrono::high_resolution_clock::now();
        total_inner_us += chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
    }

    string encoded;
    if (strCFormat == "Binary") WriteStringToFile(cipher, cipherTextFile);
    else if (strCFormat == "Hex") {
        encoded = hexencode((const CryptoPP::byte*)cipher.data(), cipher.size());
        WriteStringToFile(encoded, cipherTextFile);
    }
    else if (strCFormat == "Base64") {
        encoded = base64encode((const CryptoPP::byte*)cipher.data(), cipher.size());
        WriteStringToFile(encoded, cipherTextFile);
    }

    return total_inner_us;
}
// AES decrypt
long long AESDecrypt(const char *mode, const char *keyIVFormat, const char *keyFile, const char *ivFile,
                     const char *cipherFormat,
                     const char *cipherTextFile, const char *recoverTextFile,
                     int INNER_ROUNDS, const string& aad = "", int tagSize = 16)
{
    string dataKey = ReadFileToString(keyFile);
    string dataIV;
    string decodedKey, decodedIV;
    string strMode(mode);
    string strFormat(keyIVFormat);
    string strCFormat(cipherFormat);

    if (strMode != "ECB")
        dataIV = ReadFileToString(ivFile);

    if (strFormat == "Binary") {
        decodedKey = dataKey;
        decodedIV = dataIV;
    } else if (strFormat == "Hex") {
        decodedKey = hexdecode(dataKey);
        decodedIV = hexdecode(dataIV);
    } else if (strFormat == "Base64") {
        decodedKey = base64decode(dataKey);
        decodedIV = base64decode(dataIV);
    }

    size_t keySize = decodedKey.size();
    size_t ivSize = decodedIV.size();
    vector<CryptoPP::byte> keyVec(keySize);
    if (keySize > 0) memcpy(keyVec.data(), decodedKey.data(), keySize);
    vector<CryptoPP::byte> ivVec(ivSize);
    if (ivSize > 0) memcpy(ivVec.data(), decodedIV.data(), ivSize);

    string cipherContent = ReadFileToString(cipherTextFile);
    string decodedCipher;
    if (strCFormat == "Binary") decodedCipher = cipherContent;
    else if (strCFormat == "Hex") decodedCipher = hexdecode(cipherContent);
    else if (strCFormat == "Base64") decodedCipher = base64decode(cipherContent);

    string recovered;
    long long total_inner_us = 0;

    for (int i = 0; i < INNER_ROUNDS; ++i)
    {
        auto t0 = chrono::high_resolution_clock::now();

        if (strMode == "ECB")
        {
            ECB_Mode<AES>::Decryption d;
            d.SetKey(keyVec.data(), (unsigned int)keySize);
            recovered.clear();
            StringSource s(decodedCipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "CBC")
        {
            CBC_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            recovered.clear();
            StringSource s(decodedCipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "OFB")
        {
            OFB_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            recovered.clear();
            StringSource s(decodedCipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "CFB")
        {
            CFB_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            recovered.clear();
            StringSource s(decodedCipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "CTR")
        {
            CTR_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            recovered.clear();
            StringSource s(decodedCipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "XTS")
        {
            XTS<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            recovered.clear();
            StringSource s(decodedCipher, true, new StreamTransformationFilter(d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING));
        }
        else if (strMode == "CCM")
        {
            recovered = Dispatch_CCM_Decrypt(tagSize, decodedCipher, keyVec.data(), keySize, ivVec.data(), ivSize, aad);
        }
        else if (strMode == "GCM")
        {
            GCM<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            recovered.clear();
            
            AuthenticatedDecryptionFilter df(d, new StringSink(recovered),
                AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION);
            
            if (!aad.empty()) {
                df.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
                df.ChannelMessageEnd(AAD_CHANNEL);
            }
            df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)decodedCipher.data(), decodedCipher.size());
            df.ChannelMessageEnd(DEFAULT_CHANNEL);
        }

        auto t1 = chrono::high_resolution_clock::now();
        total_inner_us += chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
    }

    WriteStringToFile(recovered, recoverTextFile);
    return total_inner_us;
}
// ==================== CORE BENCHMARK FUNCTIONS ====================
// Đo thời gian mã hóa/giải mã THUẦN TÚY (không đọc/ghi file)
// Trả về tổng micro giây cho INNER_ROUNDS lần thực hiện

long long AESEncrypt_Core(const string& strMode, int INNER_ROUNDS, const string& aad, int tagSize,
                          const vector<CryptoPP::byte>& keyVec, const vector<CryptoPP::byte>& ivVec,
                          const string& plain, string& cipher)
{
    size_t keySize = keyVec.size();
    size_t ivSize = ivVec.size();

    auto t0 = chrono::high_resolution_clock::now();
    for (int i = 0; i < INNER_ROUNDS; ++i)
    {
        cipher.clear();
        if (strMode == "ECB") {
            ECB_Mode<AES>::Encryption e;
            e.SetKey(keyVec.data(), (unsigned int)keySize);
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "CBC") {
            CBC_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "OFB") {
            OFB_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "CFB") {
            CFB_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "CTR") {
            CTR_Mode<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
        }
        else if (strMode == "XTS") {
            XTS<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
        }
        else if (strMode == "CCM") {
            cipher = Dispatch_CCM_Encrypt(tagSize, keyVec.data(), keySize, ivVec.data(), ivSize, aad, plain);
        }
        else if (strMode == "GCM") {
            GCM<AES>::Encryption e;
            e.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            AuthenticatedEncryptionFilter ef(e, new StringSink(cipher), false, tagSize);
            if (!aad.empty()) {
                ef.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
                ef.ChannelMessageEnd(AAD_CHANNEL);
            }
            ef.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)plain.data(), plain.size());
            ef.ChannelMessageEnd(DEFAULT_CHANNEL);
        }
    }
    auto t1 = chrono::high_resolution_clock::now();
    return chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
}

long long AESDecrypt_Core(const string& strMode, int INNER_ROUNDS, const string& aad, int tagSize,
                          const vector<CryptoPP::byte>& keyVec, const vector<CryptoPP::byte>& ivVec,
                          const string& cipher, string& recovered)
{
    size_t keySize = keyVec.size();
    size_t ivSize = ivVec.size();

    auto t0 = chrono::high_resolution_clock::now();
    for (int i = 0; i < INNER_ROUNDS; ++i)
    {
        recovered.clear();
        if (strMode == "ECB") {
            ECB_Mode<AES>::Decryption d;
            d.SetKey(keyVec.data(), (unsigned int)keySize);
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "CBC") {
            CBC_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "OFB") {
            OFB_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "CFB") {
            CFB_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "CTR") {
            CTR_Mode<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered)));
        }
        else if (strMode == "XTS") {
            XTS<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING));
        }
        else if (strMode == "CCM") {
            recovered = Dispatch_CCM_Decrypt(tagSize, cipher, keyVec.data(), keySize, ivVec.data(), ivSize, aad);
        }
        else if (strMode == "GCM") {
            GCM<AES>::Decryption d;
            d.SetKeyWithIV(keyVec.data(), (unsigned int)keySize, ivVec.data(), (unsigned int)ivSize);
            AuthenticatedDecryptionFilter df(d, new StringSink(recovered),
                AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION);
            if (!aad.empty()) {
                df.ChannelPut(AAD_CHANNEL, (const CryptoPP::byte*)aad.data(), aad.size());
                df.ChannelMessageEnd(AAD_CHANNEL);
            }
            df.ChannelPut(DEFAULT_CHANNEL, (const CryptoPP::byte*)cipher.data(), cipher.size());
            df.ChannelMessageEnd(DEFAULT_CHANNEL);
        }
    }
    auto t1 = chrono::high_resolution_clock::now();
    return chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
}
// Tạo file test nếu chưa có
void EnsureFileExists(const string& filename, size_t size) {
    ifstream f(filename);
    if (!f.good()) {
        cout << "Creating " << filename << " (" << size << " bytes)..." << endl;
        vector<char> buffer(size, 'A');
        ofstream ofs(filename, ios::binary);
        ofs.write(buffer.data(), size);
    }
}
// Generate key and iv
void GenerateKeyAndIV(const char *mode, int keySize, const char *format, const char *keyFile, const char *ivFile)
{
    string strMode(mode);
    string strFormat(format);
    AutoSeededRandomPool prng;
    int ivSize = (strMode == "CCM" || strMode == "GCM") ? 12 : 16;
    vector<CryptoPP::byte> iv(ivSize);
    vector<CryptoPP::byte> key(keySize);
    prng.GenerateBlock(key.data(), (unsigned int)keySize);
    if (strMode != "ECB") prng.GenerateBlock(iv.data(), (unsigned int)ivSize);

    if (strFormat == "Binary")
    {
        StringSource ssKey(key.data(), keySize, true, new FileSink(keyFile));
        if (strMode != "ECB") StringSource ssIV(iv.data(), ivSize, true, new FileSink(ivFile));
    }
    else if (strFormat == "Hex")
    {
        string enc = hexencode(key.data(), keySize);
        WriteStringToFile(enc, keyFile);
        if (strMode != "ECB") {
            enc = hexencode(iv.data(), ivSize);
            WriteStringToFile(enc, ivFile);
        }
    }
    else if (strFormat == "Base64")
    {
        string enc = base64encode(key.data(), keySize);
        WriteStringToFile(enc, keyFile);
        if (strMode != "ECB") {
            enc = base64encode(iv.data(), ivSize);
            WriteStringToFile(enc, ivFile);
        }
    }
}
// Print help message
void PrintHelp()
{
    std::cout << "Usage: AES_benchmark.exe <action> <args...\n"
            << "Actions:\n"
            << "  genKeyIV <mode> <keySize> <format> <keyFile> <ivFile>\n"
            << "  encrypt <mode> <keyFile> <ivFile> <inFormat> <inputFile> <outFormat> <outputFile> [--runs <n>] [--totalRounds <n>] [--aad <hex>] [--tagSize <n>]\n"
            << "  decrypt <mode> <keyFile> <ivFile> <inFormat> <inputFile> <outFormat> <outputFile> [--runs <n>] [--totalRounds <n>] [--aad <hex>] [--tagSize <n>]\n"
            << "  help\n"
            << "  full_auto: Run full benchmark suite (no additional args)\n"
            << "Modes: ECB, CBC, CFB, OFB, CTR, XTS, GCM, CCM\n"
            << "Key Sizes: 16, 24, 32 bytes\n"
            << "Formats: Binary, Hex, Base64\n"
            << "Options:\n"
            << "  --runs <n>: Number of runs per round (default: 30)\n"
            << "  --totalRounds <n>: Total number of rounds (default: 1)\n"
            << "  --aad <hex>: AAD in hex (for GCM/CCM)\n"
            << "  --tagSize <n>: Tag size in bytes (for GCM/CCM, default: 16)\n";
}
// Main function
int main(int argc, char *argv[])
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
    if (argc < 2) {
        PrintHelp();
        return 1;
    }
    string action(argv[1]);
    if (action == "help") {
        PrintHelp();
        return 0;
    }
    int runs = 30;
    int totalRounds = 1;
    int tagSize = 16;
    string aadHex = "";
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--runs") == 0 && i + 1 < argc) runs = atoi(argv[i+1]);
        if (strcmp(argv[i], "--totalRounds") == 0 && i + 1 < argc) totalRounds = atoi(argv[i+1]);
        if (strcmp(argv[i], "--tagSize") == 0 && i + 1 < argc) tagSize = atoi(argv[i+1]);
        if (strcmp(argv[i], "--aad") == 0 && i + 1 < argc) aadHex = argv[i+1];
    }
    string aad = aadHex.empty() ? "" : hexdecode(aadHex);
        if (action == "full_auto")
    {
        // Tạo thư mục đầu ra nếu chưa có
        fs::create_directories("output/windows");
        vector<string> files = {"1KiB.bin", "4KiB.bin", "16KiB.bin", "256KiB.bin", "1MiB.bin", "8MiB.bin"};
        vector<size_t> sizes = {1024, 4096, 16384, 262144, 1048576, 8388608};
        vector<string> modes = {"ECB", "CBC", "CFB", "OFB", "CTR", "XTS", "GCM", "CCM"};

        for (size_t f = 0; f < files.size(); ++f) {
            EnsureFileExists(files[f], sizes[f]);
            string csvPath = "output/windows/benchmark_" + files[f] + ".csv";
            ofstream csv(csvPath);
            csv << "Mode,File,Size,Operation,Run,Time(s),Throughput(MB/s)\n";
            cout << "\n========== Benchmarking " << files[f] << " ==========" << endl;

            for (const string& m : modes) {
                if (m == "CCM" && sizes[f] > 65535) continue;

                int keySize = (m == "XTS") ? 32 : 16;
                string aad_data = (m == "GCM" || m == "CCM") ? "123456" : "";
                int tSize = (m == "GCM" || m == "CCM") ? 16 : 0;

                for (string op : {"encrypt", "decrypt"}) {
                    cout << "   > " << m << " " << op << "..." << flush;

                    AutoSeededRandomPool prng;
                    vector<CryptoPP::byte> k(keySize), iv((m == "CCM" || m == "GCM") ? 12 : 16);
                    prng.GenerateBlock(k.data(), k.size());
                    if (m != "ECB") prng.GenerateBlock(iv.data(), iv.size());

                    string inputData = ReadFileToString(files[f].c_str());
                    string dummy;

                    // Warm‑up (2 rounds)
                    for (int w = 0; w < 2; ++w) {
                        if (op == "encrypt")
                            AESEncrypt_Core(m, 1000, aad_data, tSize, k, iv, inputData, dummy);
                        else {
                            string cipher;
                            AESEncrypt_Core(m, 1, aad_data, tSize, k, iv, inputData, cipher);
                            AESDecrypt_Core(m, 1000, aad_data, tSize, k, iv, cipher, dummy);
                        }
                    }

                    long long total_core_us = 0;
                    auto overall_start = chrono::steady_clock::now();

                    vector<double> latencies;
                    for (int r = 0; r < 30; ++r) {
                        long long t_us = 0;
                        if (op == "encrypt")
                            t_us = AESEncrypt_Core(m, 1000, aad_data, tSize, k, iv, inputData, dummy);
                        else {
                            string cipher;
                            AESEncrypt_Core(m, 1, aad_data, tSize, k, iv, inputData, cipher);
                            t_us = AESDecrypt_Core(m, 1000, aad_data, tSize, k, iv, cipher, dummy);
                        }
                        total_core_us += t_us;
                        double sec_per_op = t_us / 1'000'000'000.0;
                        latencies.push_back(sec_per_op);
                        double throughput = (sizes[f] / (1024.0 * 1024.0)) / sec_per_op;
                        csv << m << "," << files[f] << "," << sizes[f] << ","
                            << (op == "encrypt" ? "Encrypt" : "Decrypt") << ","
                            << r << "," << sec_per_op << "," << throughput << "\n";
                    }

                    auto overall_end = chrono::steady_clock::now();
                    auto dur_ms = chrono::duration_cast<chrono::milliseconds>(overall_end - overall_start).count();
                    double total_ms = total_core_us / 1000.0;      // tổng core time (ms)
                    double avg_ms = total_ms / 30.0;               // 30 runs, mỗi run 1000 ops
                    cout << endl;
                    cout << "Mode: " << m << " | Operation: " << (op == "encrypt" ? "Encrypt" : "Decrypt") << endl;
                    cout << "Total elapsed time: " << dur_ms << " ms" << endl;
                    cout << "Total core time: " << fixed << setprecision(6) << total_ms << " ms" << endl;
                    cout << "Average core time: " << fixed << setprecision(6) << avg_ms << " ms" << endl;
                }
            }
            csv.close();
        }
        cout << "\nFull-Auto benchmark completed. CSV files saved to output/windows/" << endl;
        return 0;
    }
    else
    if (action == "genKeyIV")
    {
        GenerateKeyAndIV(argv[2], stoi(argv[3]), argv[4], argv[5], argv[6]);
    }
    else if (action == "encrypt")
    {
        size_t fileSize = 0;
        try { fileSize = fs::file_size(argv[7]); } catch(...) {}
        double sizeMB = fileSize / (1024.0 * 1024.0);

        // Mở file CSV
        fs::create_directories("output/windows");
        string csvPath = string("output/windows/benchmark_") + argv[7] + ".csv";
        ofstream csv(csvPath);
        csv << "Mode,File,Size,Operation,Run,Time(s),Throughput(MB/s)\n";

        long long total_us = 0;
        using clock = chrono::steady_clock;
        auto overall_start = clock::now();
        for (int t = 0; t < totalRounds; ++t) {
            for (int i = 0; i < runs; ++i) {
                long long took = AESEncrypt(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], 1, aad, tagSize);
                total_us += took;

                // Ghi CSV: took là micro giây cho 1 lần (INNER_ROUNDS=1)
                double timeSec = took / 1'000'000.0;   // đổi sang giây
                double throughput = sizeMB / timeSec;
                csv << argv[2] << "," << argv[7] << "," << fileSize << ",Encrypt,"
                << (t * runs + i) << "," << timeSec << "," << throughput << "\n";
            }
        }
        csv.close();

        auto overall_end = clock::now();
        auto dur_ms = chrono::duration_cast<chrono::milliseconds>(overall_end - overall_start).count();
        long long totalRunsAll = (long long) totalRounds * (long long) runs;
        
        long long ms = dur_ms % 1000;
        long long total_seconds = dur_ms / 1000;
        long long seconds = total_seconds % 60;
        long long total_minutes = total_seconds / 60;
        long long minutes = total_minutes % 60;
        long long hours = total_minutes / 60;

        cout << "Total elapsed time: "
             << hours << "h:"
             << setw(2) << setfill('0') << minutes << "m:"
             << setw(2) << setfill('0') << seconds << "s."
             << setw(3) << setfill('0') << ms << "ms\n";

        double total_ms = total_us / 1000.0;
        double avg_ms = total_ms / (double)totalRunsAll;
        cout << "Total core time: " << fixed << setprecision(6) << total_ms << " ms" << endl;
        cout << "Average core time: " << fixed << setprecision(6) << avg_ms << " ms" << endl;
    }
    else if (action == "decrypt")
    {
        size_t fileSize = 0;
        try { fileSize = fs::file_size(argv[7]); } catch(...) {}
        double sizeMB = fileSize / (1024.0 * 1024.0);

        // Mở file CSV
        fs::create_directories("output/windows");
        string csvPath = string("output/windows/benchmark_") + argv[7] + ".csv";
        ofstream csv(csvPath);
        csv << "Mode,File,Size,Operation,Run,Time(s),Throughput(MB/s)\n";

        long long total_us = 0;
        using clock = chrono::steady_clock;
        auto overall_start = clock::now();
        for (int t = 0; t < totalRounds; ++t) {
            for (int i = 0; i < runs; ++i) {
                long long took = AESDecrypt(argv[2], argv[3], argv[4], argv[5], argv[6], argv[7], argv[8], 1, aad, tagSize);
                total_us += took;

                double timeSec = took / 1'000'000.0;   // đổi sang giây
                double throughput = sizeMB / timeSec;
                csv << argv[2] << "," << argv[7] << "," << fileSize << ",Decrypt,"
                << (t * runs + i) << "," << timeSec << "," << throughput << "\n";
            }
        }
        csv.close();

        auto overall_end = clock::now();
        auto dur_ms = chrono::duration_cast<chrono::milliseconds>(overall_end - overall_start).count();
        long long totalRunsAll = (long long) totalRounds * (long long) runs;
        
        long long ms = dur_ms % 1000;
        long long total_seconds = dur_ms / 1000;
        long long seconds = total_seconds % 60;
        long long total_minutes = total_seconds / 60;
        long long minutes = total_minutes % 60;
        long long hours = total_minutes / 60;

        cout << "Total elapsed time: "
             << hours << "h:"
             << setw(2) << setfill('0') << minutes << "m:"
             << setw(2) << setfill('0') << seconds << "s."
             << setw(3) << setfill('0') << ms << "ms\n";

        double total_ms = total_us / 1000.0;
        double avg_ms = total_ms / (double)totalRunsAll;
        cout << "Total core time: " << fixed << setprecision(6) << total_ms << " ms" << endl;
        cout << "Average core time: " << fixed << setprecision(6) << avg_ms << " ms" << endl;
    }
    return 0;
}

