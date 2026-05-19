#include<cryptopp/aes.h>
#include<cryptopp/modes.h>
#include<cryptopp/filters.h>
#include<cryptopp/hex.h>
#include<cryptopp/files.h>
#include<cryptopp/xts.h>
#include<cryptopp/gcm.h>
#include <cryptopp/ccm.h>
#include <cryptopp/base64.h>

#include<iostream> 
#include <fstream>
#include <string>
#include<sstream>
#include<vector>
#include<iomanip>
#include <cryptopp/cryptlib.h>
#include <filesystem>
#include <iomanip>
namespace fs = std::filesystem;

using namespace CryptoPP;
using CryptoPP::byte;

// ./AES_KAT --kat

// Modes: CBC - OFB - ECB - GCM - CCM(encrypt) 
// ---------------- Utility ----------------
static void trim(std::string &s) {
    size_t a = 0; while (a < s.size() && isspace((unsigned char)s[a])) ++a; // Delete space in head
    size_t b = s.size(); while (b > a && isspace((unsigned char)s[b-1])) --b; // Delete space in tail
    s = s.substr(a, b - a);
}

//Convert hex string to raw bytes
std::string HexToBytes(const std::string &hex)
{
    std::string decoded;
    StringSource(hex, true, new HexDecoder(new StringSink(decoded)));
    return decoded;
}

// Convert base64 string to raw bytes
std::string Base64ToBytes(const std::string& b64) {
    std::string bytes;
    StringSource(b64, true,
        new Base64Decoder(new StringSink(bytes))
    );
    return bytes;
}

// Convert raw bytes to base64 string
std::string BytesToBase64(const std::string& bytes) {
    std::string b64;
    StringSource(bytes, true,
        new Base64Encoder(new StringSink(b64), false)
    );
    return b64;
}

// Convert raw bytes to hex string
std::string ByteToHex(const byte* data, size_t len)
{
    std::string decoded;
    StringSource(data, len, true, new HexEncoder(new StringSink(decoded)));
    return decoded;
}

// Convert bytes string to hex string
std::string BytesToHex(const std::string& bytes) {
    std::string hex;
    StringSource(bytes, true,
        new HexEncoder(new StringSink(hex), false)
    );
    return hex;
}

std::string normalizeCFB1Output(const std::string& s)
{
    std::string out;
    for(byte b : s) out += (b & 0x01) ? '1' : '0';
    return out;
}

// CFB1: Encrypt/Decrypt one bit at a time
std::string AES_CFB1_Encrypt(const byte* key, size_t keyLen, const byte* iv, size_t ivLen, const std::string& plaintextBit)
{
    // plaintextBit is a raw byte string from HexToBytes (e.g., "\x00" or "\x01")
    // If input was "1" -> HexToBytes("01") -> "\x01" -> (byte)1
    byte inputByte = (byte)plaintextBit[0];
    byte inputBit = (inputByte & 0x01);
    
    // Copy IV to working register (128 bits = 16 bytes)
    byte shiftReg[16];
    memcpy(shiftReg, iv, 16);
    
    // Encrypt shift register with AES ECB
    ECB_Mode<AES>::Encryption ecb;
    ecb.SetKey(key, keyLen);
    
    byte keystream[16];
    ecb.ProcessData(keystream, shiftReg, 16);
    
    // Extract MSB (most significant bit) of keystream
    byte keystreamBit = (keystream[0] >> 7) & 0x01;
    
    // XOR plaintext bit with keystream bit
    byte ciphertextBit = inputBit ^ keystreamBit;

    // Return as raw byte \x00 or \x01
    return std::string(1, (char)ciphertextBit);
}

std::string AES_CFB1_Decrypt(const byte* key, size_t keyLen, const byte* iv, size_t ivLen, const std::string& ciphertextBit)
{
    // CFB1 decrypt is same as encrypt (XOR is symmetric)
    return AES_CFB1_Encrypt(key, keyLen, iv, ivLen, ciphertextBit);
}

// Helper to execute encryption with specific T_Size
template <int T_Size>
std::string Run_CCM_Encrypt(const byte* key, size_t keyLen, const byte* iv, size_t ivLen,
                            const std::string& aad, const std::string& plaintext, size_t tagLen)
{
    // CCM<AES, T_Size> uses T_Size as default digest size.
    // L calculated dynamically from ivLen (m_L = 15 - ivLen)
    typename CCM<AES, T_Size>::Encryption enc;
    enc.SetKeyWithIV(key, keyLen, iv, ivLen);
    enc.SpecifyDataLengths(aad.size(), plaintext.size(), 0);

    std::string ciphertext;
    AuthenticatedEncryptionFilter ef(
        enc,
        new StringSink(ciphertext),
        false, // no padding
        tagLen // mac length
    );

    ef.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
    ef.ChannelMessageEnd(AAD_CHANNEL);

    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    return ciphertext;
}

// Helper to execute decryption with specific T_Size
template <int T_Size>
std::string Run_CCM_Decrypt(const std::string& ciphertext, const byte* key, size_t keyLen, 
                            const byte* iv, size_t ivLen, const std::string& aad, size_t tagLen)
{
    typename CCM<AES, T_Size>::Decryption dec;
    dec.SetKeyWithIV(key, keyLen, iv, ivLen);
    
    size_t ctLen = ciphertext.size();
    if (ctLen < tagLen) throw std::runtime_error("Ciphertext too short for tag");
    size_t msgLen = ctLen - tagLen;
    dec.SpecifyDataLengths(aad.size(), msgLen, 0);

    std::string plaintext;
    AuthenticatedDecryptionFilter df(
        dec,
        new StringSink(plaintext),
        AuthenticatedDecryptionFilter::MAC_AT_END | AuthenticatedDecryptionFilter::THROW_EXCEPTION, 
        (int)tagLen
    );

    df.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
    df.ChannelMessageEnd(AAD_CHANNEL);

    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());
    df.ChannelMessageEnd(DEFAULT_CHANNEL);

    return plaintext;
}

// Dispatch on Tag Size (T) - L is dynamic inside CCM
std::string Dispatch_CCM_Encrypt(int tagLen, int L, const byte* k, size_t kl, const byte* i, size_t il, const std::string& a, const std::string& p) {
    switch(tagLen) {
        case 4: return Run_CCM_Encrypt<4>(k, kl, i, il, a, p, tagLen);
        case 6: return Run_CCM_Encrypt<6>(k, kl, i, il, a, p, tagLen);
        case 8: return Run_CCM_Encrypt<8>(k, kl, i, il, a, p, tagLen);
        case 10: return Run_CCM_Encrypt<10>(k, kl, i, il, a, p, tagLen);
        case 12: return Run_CCM_Encrypt<12>(k, kl, i, il, a, p, tagLen);
        case 14: return Run_CCM_Encrypt<14>(k, kl, i, il, a, p, tagLen);
        case 16: return Run_CCM_Encrypt<16>(k, kl, i, il, a, p, tagLen);
        default: throw std::runtime_error("Invalid Tag Length");
    }
}

std::string Dispatch_CCM_Decrypt(int tagLen, int L, const std::string& ct, const byte* k, size_t kl, const byte* i, size_t il, const std::string& a) {
    switch(tagLen) {
        case 4: return Run_CCM_Decrypt<4>(ct, k, kl, i, il, a, tagLen);
        case 6: return Run_CCM_Decrypt<6>(ct, k, kl, i, il, a, tagLen);
        case 8: return Run_CCM_Decrypt<8>(ct, k, kl, i, il, a, tagLen);
        case 10: return Run_CCM_Decrypt<10>(ct, k, kl, i, il, a, tagLen);
        case 12: return Run_CCM_Decrypt<12>(ct, k, kl, i, il, a, tagLen);
        case 14: return Run_CCM_Decrypt<14>(ct, k, kl, i, il, a, tagLen);
        case 16: return Run_CCM_Decrypt<16>(ct, k, kl, i, il, a, tagLen);
        default: throw std::runtime_error("Invalid Tag Length");
    }
}

// ---------------- AES-ENCRYPT ----------------
std::string AESEncrypt(const std::string& mode, const std::string& plaintext, const byte* key, size_t keyLen, const byte* iv, size_t ivLen, const std::string& aad, std::string& tag, size_t tagLen, bool usePadding)
{
    try
    {
        std::string ciphertext;

        if (mode == "CBC")
        {
            CBC_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext), usePadding ? BlockPaddingSchemeDef::PKCS_PADDING : StreamTransformationFilter::NO_PADDING));
            return ciphertext;
        }
        else if (mode == "CFB")
        {
             if (usePadding)  // CFB1 mode - manual bit-level implementation
            {
               return AES_CFB1_Encrypt(key, keyLen, iv, ivLen, plaintext);
            }
            else {  // CFB8 or CFB128 - byte-level feedback
                CFB_Mode<AES>::Encryption enc;
                enc.SetKeyWithIV(key, keyLen, iv, ivLen);
                StringSource(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext), StreamTransformationFilter::NO_PADDING));
            }
            return ciphertext;
        }
        else if(mode == "OFB")
        {
             OFB_Mode<AES>::Encryption enc;
            enc.SetKeyWithIV(key, keyLen, iv, ivLen);
             StringSource(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext), StreamTransformationFilter::NO_PADDING));
             return ciphertext;
        }
        else if(mode == "ECB")
        {
             ECB_Mode<AES>::Encryption enc;
             enc.SetKey(key, keyLen);
             StringSource(plaintext, true, new StreamTransformationFilter(enc, new StringSink(ciphertext), usePadding ? BlockPaddingSchemeDef::PKCS_PADDING : StreamTransformationFilter::NO_PADDING));
             return ciphertext;
        }
        else if(mode == "CTR")
        {
            CTR_Mode<AES>::Encryption enc_ctr;
            enc_ctr.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(plaintext, true, new StreamTransformationFilter(enc_ctr, new StringSink(ciphertext)));
            return ciphertext;
        }
        else if(mode == "CCM")
        {
            int L = 15 - (int)ivLen;
            return Dispatch_CCM_Encrypt(static_cast<int>(tagLen), L, key, keyLen, iv, ivLen, aad, plaintext);
        }
        else if (mode == "GCM") {
            GCM<AES>::Encryption enc_gcm;
            enc_gcm.SetKeyWithIV(key, keyLen, iv, ivLen);
            enc_gcm.SpecifyDataLengths(aad.size(), plaintext.size(), 0);

            AuthenticatedEncryptionFilter ef(
                enc_gcm,
                new StringSink(ciphertext),
                false,
                static_cast<int>(tagLen)
            );

            ef.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
            ef.ChannelMessageEnd(AAD_CHANNEL);

            ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());
            ef.ChannelMessageEnd(DEFAULT_CHANNEL);

            size_t actualTagLen = tagLen;
            if (ciphertext.size() < actualTagLen) return ""; 

            std::string actualCipher = ciphertext.substr(0, ciphertext.size() - actualTagLen);
            std::string actualTag = ciphertext.substr(ciphertext.size() - actualTagLen);
            
            tag = BytesToHex(actualTag); 
            return actualCipher;         
        }
        else if(mode == "XTS")
        {
            XTS_Mode<AES>::Encryption enc_xts;
            enc_xts.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(plaintext, true, new StreamTransformationFilter(enc_xts, new StringSink(ciphertext), StreamTransformationFilter::NO_PADDING));
            return ciphertext;
        }

        return ciphertext;

    }
    catch (const CryptoPP::Exception& e)
    {
        return "";
    }
}

// ---------------- AES-DECRYPT ----------------
std::string AESDecrypt(const std::string& mode, const std::string& ciphertext, const byte* key, size_t keyLen, const byte* iv, size_t ivLen, const std::string& aad, const std::string& tagHex, size_t tagLen, bool usePadding)
{
    std::string plaintext;
    if (mode == "CBC")
    {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext), usePadding ? BlockPaddingSchemeDef::PKCS_PADDING : StreamTransformationFilter::NO_PADDING));
            return plaintext;
    }
    else if (mode == "CFB")
    {
            if (usePadding)  // CFB1 mode - manual bit-level implementation
            {
                return AES_CFB1_Decrypt(key, keyLen, iv, ivLen, ciphertext);
            }
            else {  // CFB8 or CFB128 - byte-level feedback
                CFB_Mode<AES>::Decryption dec;
                dec.SetKeyWithIV(key, keyLen, iv, ivLen);
                StringSource(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext), StreamTransformationFilter::NO_PADDING));
            }
            return plaintext;
    }
    else if(mode == "OFB")
    {
            OFB_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext), StreamTransformationFilter::NO_PADDING));
            return plaintext;

    }
    else if(mode == "ECB")
    {
            ECB_Mode<AES>::Decryption dec;
            dec.SetKey(key, keyLen);
            StringSource(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext), usePadding ? BlockPaddingSchemeDef::PKCS_PADDING : StreamTransformationFilter::NO_PADDING));
            return plaintext;
    }
    else if(mode == "CTR")
    {
            CTR_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext))); 
            return plaintext;
    }
    else if (mode == "CCM") {
        int L = 15 - (int)ivLen;
        return Dispatch_CCM_Decrypt(static_cast<int>(tagLen), L, ciphertext, key, keyLen, iv, ivLen, aad);
    }
    else if (mode == "GCM") {
        std::string tagBytes = HexToBytes(tagHex);
        size_t tagBytesLen = tagBytes.size();

        GCM<AES>::Decryption dec_gcm;
        dec_gcm.SetKeyWithIV(key, keyLen, iv, ivLen);

        AuthenticatedDecryptionFilter adf(
            dec_gcm,
            new StringSink(plaintext),
            AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
            (int)tagBytesLen 
        );

        if (!aad.empty()) {
            adf.ChannelPut(AAD_CHANNEL, (const byte*)aad.data(), aad.size());
            adf.ChannelMessageEnd(AAD_CHANNEL);
        }

        adf.ChannelPut(DEFAULT_CHANNEL, (const byte*)ciphertext.data(), ciphertext.size());
        adf.ChannelPut(DEFAULT_CHANNEL, (const byte*)tagBytes.data(), tagBytesLen);
        adf.ChannelMessageEnd(DEFAULT_CHANNEL);

        if (!adf.GetLastResult()) return ""; 
        return plaintext;
    }
    else if (mode == "XTS")
    {
            XTS_Mode<AES>::Decryption dec;
            dec.SetKeyWithIV(key, keyLen, iv, ivLen);
            StringSource(ciphertext, true, new StreamTransformationFilter(dec, new StringSink(plaintext), StreamTransformationFilter::NO_PADDING));
            return plaintext;
    }
    return plaintext;
}
// CBC - CFB - ECB - OFB
struct TestVector {
    int count = -1;
    std::string KEY, IV, PLAINTEXT, CIPHERTEXT;
    bool encrypt = true;
};
// CCM
struct TestVTCCM {
    int count = -1;
    int Alen = 0, Plen = 0, Nlen = 0, Tlen = 0;
    std::string KEY, NONCE, ADATA, PAYLOAD, CIPHERTEXT, RESULT;
};
// GCM
struct TestVTGCM{
    int count = -1;
    std::string Key, IV, CT, AAD, Tag, PT;
    size_t tagLen, ivLen;
    bool shouldFail = false;
};

// Phân tích vector của CBC
static std::vector<TestVector> ParseRsp_CBC(const std::string& path) {
    std::string text;
    try { FileSource fs(path.c_str(), true, new StringSink(text)); }
    catch(const Exception& e) { 
        std::cerr << "ParseRsp_CBC Error reading " << path << ": " << e.what() << std::endl;
        return {}; 
    }
    if (text.empty()) { std::cerr << "ParseRsp_CBC: File is empty: " << path << std::endl; return {}; }
    std::istringstream iss(text); 
    std::string line;
    std::vector<TestVector> list;
    TestVector cur;
    bool encryptMode = true;
    bool isCFB1 = (path.find("CFB1") != std::string::npos);

    while (std::getline(iss, line)) {
        trim(line);
        if (line.empty() || line[0]=='#') continue;
        
        if (line == "[ENCRYPT]") { encryptMode = true; continue; }
        if (line == "[DECRYPT]") { encryptMode = false; continue; }

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq+1);
        trim(k); trim(v);
        if (k == "COUNT") {
            if (cur.count != -1 && !cur.KEY.empty() && !cur.PLAINTEXT.empty())
                list.push_back(cur);
            cur = TestVector();
            cur.count = std::stoi(v);
            cur.encrypt = encryptMode;
        } else if (k == "KEY") cur.KEY = v;
        else if (k == "IV") cur.IV = v;
        else if (k == "PLAINTEXT") {
            if (isCFB1 && (v == "0" || v == "1")) {
                cur.PLAINTEXT = (v == "0") ? "00" : "01";
            } else {
                cur.PLAINTEXT = v;
            }
        }
        else if (k == "CIPHERTEXT") {
            if (isCFB1 && (v == "0" || v == "1")) {
                cur.CIPHERTEXT = (v == "0") ? "00" : "01";
            } else {
                cur.CIPHERTEXT = v;
            }
        }
    }
    if (cur.count != -1 && !cur.KEY.empty()) list.push_back(cur);
    return list;
}
// Phân tích vector của CCM
static std::vector<TestVTCCM> ParseRsp_CCM(const std::string& path) {
    std::ifstream ifs(path);
    if (!ifs) {
        std::cerr << "ParseRsp_CCM: Cannot open file: " << path << std::endl;
        throw std::runtime_error("Cannot open file: " + path);
    }

    std::vector<TestVTCCM> tests;

    // global/current values
    std::string curKey, curNonce;
    int curAlen = -1, curPlen = -1, curNlen = -1, curTlen = -1;

    TestVTCCM curTest;
    bool haveTest = false;

    std::string line;

    while (std::getline(ifs, line)) {
        trim(line);
        if (line.empty() || line[0] == '#') continue;
        
        // Remove brackets if present
        if (line.front() == '[' && line.back() == ']') {
            line = line.substr(1, line.size() - 2);
        }

        // Handle multiple assignments in one line separated by commas
        std::stringstream ss(line);
        std::string segment;
        
        while(std::getline(ss, segment, ',')) {
            trim(segment); 
            if(segment.empty()) continue;

            auto pos = segment.find('=');
            if (pos == std::string::npos) continue;

            std::string key = segment.substr(0, pos);
            std::string right = segment.substr(pos + 1);
            trim(key); 
            trim(right);

            // Parsing logic
            if (key == "Alen") {
                try { curAlen = std::stoi(right); } catch(...) { curAlen = -1; }
                if (haveTest && curTest.count < 0) curTest.Alen = curAlen;
            }
            else if (key == "Plen") {
                try { curPlen = std::stoi(right); } catch(...) { curPlen = -1; }
                if (haveTest && curTest.count < 0) curTest.Plen = curPlen;
            }
            else if (key == "Nlen") {
                // Flush current test if exists before changing Nlen section
                if (haveTest && curTest.count >= 0) {
                    tests.push_back(curTest);
                    curTest = TestVTCCM();
                    haveTest = false;
                }
                try { curNlen = std::stoi(right); } catch(...) { curNlen = -1; }
            }
            else if (key == "Tlen") {
                try { curTlen = std::stoi(right); } catch(...) { curTlen = -1; }
                if (haveTest && curTest.count < 0) curTest.Tlen = curTlen;
            }
            else if (key == "Key") {
                if (haveTest && curTest.count >= 0) {
                     tests.push_back(curTest);
                     curTest = TestVTCCM();
                     haveTest = false;
                }
                curKey = right;
                if (haveTest) curTest.KEY = curKey;
            }
            else if (key == "Nonce") {
                if (haveTest && curTest.count >= 0) {
                     tests.push_back(curTest);
                     curTest = TestVTCCM();
                     haveTest = false;
                }
                curNonce = right;
                if (haveTest) curTest.NONCE = curNonce;
            }
            else if (key == "Count") {
                if (haveTest && curTest.count >= 0) {
                    tests.push_back(curTest);
                    curTest = TestVTCCM();
                    haveTest = false;
                }
                curTest = TestVTCCM();
                haveTest = true;
                try { curTest.count = std::stoi(right); } catch(...) { curTest.count = -1; }
                
                if (!curKey.empty()) curTest.KEY = curKey;
                if (!curNonce.empty()) curTest.NONCE = curNonce;
                if (curAlen >= 0) curTest.Alen = curAlen;
                if (curPlen >= 0) curTest.Plen = curPlen;
                if (curNlen >= 0) curTest.Nlen = curNlen;
                if (curTlen >= 0) curTest.Tlen = curTlen;
            }
            else if (key == "Adata") {
                if (!haveTest) {
                    curTest = TestVTCCM(); haveTest = true;
                    if (!curKey.empty()) curTest.KEY = curKey;
                    if (!curNonce.empty()) curTest.NONCE = curNonce;
                    if (curAlen >= 0) curTest.Alen = curAlen;
                    if (curPlen >= 0) curTest.Plen = curPlen;
                    if (curNlen >= 0) curTest.Nlen = curNlen;
                    if (curTlen >= 0) curTest.Tlen = curTlen;
                }
                curTest.ADATA = right;
            }
            else if (key == "Payload") {
                if (!haveTest) {
                    curTest = TestVTCCM(); haveTest = true;
                    if (!curKey.empty()) curTest.KEY = curKey;
                    if (!curNonce.empty()) curTest.NONCE = curNonce;
                    if (curAlen >= 0) curTest.Alen = curAlen;
                    if (curPlen >= 0) curTest.Plen = curPlen;
                    if (curNlen >= 0) curTest.Nlen = curNlen;
                    if (curTlen >= 0) curTest.Tlen = curTlen;
                }
                curTest.PAYLOAD = right;
            }
            else if (key == "CT" || key == "Ciphertext") {
                if (!haveTest) {
                    curTest = TestVTCCM(); haveTest = true;
                    if (!curKey.empty()) curTest.KEY = curKey;
                    if (!curNonce.empty()) curTest.NONCE = curNonce;
                    if (curAlen >= 0) curTest.Alen = curAlen;
                    if (curPlen >= 0) curTest.Plen = curPlen;
                    if (curNlen >= 0) curTest.Nlen = curNlen;
                    if (curTlen >= 0) curTest.Tlen = curTlen;
                }
                curTest.CIPHERTEXT = right;
            }
            else if (key == "Result" || key == "Tag") {
                if (!haveTest) {
                    curTest = TestVTCCM(); haveTest = true;
                    if (!curKey.empty()) curTest.KEY = curKey;
                    if (!curNonce.empty()) curTest.NONCE = curNonce;
                    if (curAlen >= 0) curTest.Alen = curAlen;
                    if (curPlen >= 0) curTest.Plen = curPlen;
                    if (curNlen >= 0) curTest.Nlen = curNlen;
                    if (curTlen >= 0) curTest.Tlen = curTlen;
                }
                curTest.RESULT = right;
            }
        }
    }

    // Push final test only if it has valid Count
    if (haveTest && curTest.count >= 0 && (!curTest.CIPHERTEXT.empty() || !curTest.PAYLOAD.empty())) {
        tests.push_back(curTest);
    }
    

    return tests;
}
// Phân tích vector GCM
static std::vector<TestVTGCM> ParseRsp_GCM(const std::string& path) { 
    std::ifstream file(path);
    if (!file.good()) {
        std::cerr << "ParseRsp_GCM: Cannot open: " << path << "\n";
        return {};
    }

    std::vector<TestVTGCM> vecs;
    TestVTGCM cur;
    std::string line;
    size_t currentTaglen = -1;

    while (std::getline(file, line)) {
        trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            // dòng kiểu [Nlen = 7]
            line = line.substr(1, line.size() - 2);
        }

        if (line.front() == '[' && line.back() == ']') {
            // dòng kiểu [Nlen = 7]
            line = line.substr(1, line.size() - 2);
        }
    
        // Key-value lines
        // Check for standalone FAIL marker first
        if (line == "FAIL") {
            cur.shouldFail = true;
            continue;
        }
        
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        trim(k); trim(v);

        if (k == "Taglen") {
            currentTaglen = std::stoi(v) / 8; // Bits to Bytes
        }
        else if (k == "Count" || k == "COUNT") {
            if (cur.count != -1 && !cur.Key.empty())
                vecs.push_back(cur);
            cur = TestVTGCM();
            cur.count = std::stoi(v);
            cur.tagLen = currentTaglen; // gán Taglen hiện tại cho Count mới
        }
        else if (k == "Key") cur.Key = v;
        else if (k == "IV") cur.IV = v;
        else if (k == "PT") cur.PT = v;
        else if (k == "AAD") cur.AAD = v;
        else if (k == "CT") cur.CT = v;
        else if (k == "Tag") {
            cur.Tag = v;
            cur.shouldFail = false;
        }
        else if (k == "FAIL") {
            cur.shouldFail = true;
        }
    }

    if (cur.count != -1 && !cur.Key.empty())
        vecs.push_back(cur);

    return vecs;
}

static void RunKat() // chưa thêm iv len
{
    const std::string basePath = "KAT/";
    const std::vector<std::string> folders = {
        basePath + "KAT_AES",
        basePath + "ccmtestvectors",
        basePath + "gcmtestvectors",
        basePath + "CFB"
    };

    std::ofstream csv("output/kat_results.csv");
    csv << "filename,COUNT,pass\n";

    long totalAll = 0, passAll = 0;

    for (const auto& folder : folders)
    {
        std::string mode;
        if (folder.find("KAT_AES") != std::string::npos) mode = "CBC";
        else if (folder.find("ccm") != std::string::npos) mode = "CCM";
        else if (folder.find("gcm") != std::string::npos) mode = "GCM";
        // else if (folder.find("CFB") != std::string::npos) mode = "CBC";
        else continue;

        std::cout << "\n=== Running mode: " << mode << " in " << folder << " ===\n";

        if (!fs::exists(folder)) {
            std::cout << "Folder not found: " << folder << " - skipping\n";
            continue;
        }

        for (auto& file : fs::directory_iterator(folder))
        {
            if (!file.is_regular_file() || file.path().extension() != ".rsp")
                continue;

            std::string path = file.path().string();
            std::string name = file.path().filename().string();
            std::cout << "\n--> " << name << std::endl;

            long total = 0, pass = 0;

            if (mode == "CBC" || mode == "OFB" || mode == "CFB" || mode == "ECB")
            { 
               auto tests = ParseRsp_CBC(path); // Function name matches file content
               for (auto& v : tests) {
                   ++total;
                   std::string key = HexToBytes(v.KEY);
                   std::string iv = HexToBytes(v.IV);
                   std::string pt = HexToBytes(v.PLAINTEXT);
                   std::string ct = HexToBytes(v.CIPHERTEXT);
                   
                   std::string currentMode = mode;
                   if (name.find("CBC") != std::string::npos) currentMode = "CBC";
                   else if (name.find("ECB") != std::string::npos) currentMode = "ECB";
                   else if (name.find("CFB") != std::string::npos) currentMode = "CFB";
                   else if (name.find("OFB") != std::string::npos) currentMode = "OFB";

                   // Fix: Strictly identifying CFB1 (must NOT be CFB128)
                   bool cfb1 = (name.find("CFB1") != std::string::npos) && (name.find("CFB128") == std::string::npos);

                   std::string res;
                   if (v.encrypt) {
                       std::string tag; 
                       res = AESEncrypt(currentMode, pt, (const byte*)key.data(), key.size(), (const byte*)iv.data(), iv.size(), "", tag, 0, cfb1);
                       if (BytesToHex(res) == v.CIPHERTEXT) ++pass;
                       csv << name << "," << v.count << "," << ((BytesToHex(res) == v.CIPHERTEXT) ? "1" : "0") << "\n";
                   }
                   else {
                       res = AESDecrypt(currentMode, ct, (const byte*)key.data(), key.size(), (const byte*)iv.data(), iv.size(), "", "", 0, cfb1);
                       if (BytesToHex(res) == v.PLAINTEXT) ++pass;
                       csv << name << "," << v.count << "," << ((BytesToHex(res) == v.PLAINTEXT) ? "1" : "0") << "\n";
                   }
               }
            }
            else if (mode == "CCM")
            {
                auto tests = ParseRsp_CCM(path);
                bool isDecrypt = (name.find("DVPT") != std::string::npos); // DVPT is decryption verification

                for (auto& v : tests) {
                    ++total;
                    if (v.KEY.empty()) continue;

                    std::string key = HexToBytes(v.KEY);
                    std::string nonce = HexToBytes(v.NONCE);
                    std::string aad = HexToBytes(v.ADATA); 
                    if (v.Alen == 0) aad = ""; // Handle empty AAD explicitly
         
                    bool ok = false;

                    if (isDecrypt) 
                    {
                        // DVPT: Verify Decryption
                        // Input: CT (Ciphertext || Tag), Key, Nonce, AAD
                        // Output Check: Result (Pass/Fail) and Payload (if Pass)
                        
                        std::string ct = HexToBytes(v.CIPHERTEXT);
                        std::string expectedPayload = "";
                        
                        // Handle strict empty payload - NIST uses "00" for empty if Plen=0
                        if (v.Plen == 0) expectedPayload = "";
                        else expectedPayload = HexToBytes(v.PAYLOAD);

                        // Try to decrypt
                        std::string pt_calc;
                        bool decryptSuccess = false;
                        try {
                             pt_calc = AESDecrypt("CCM", ct, 
                                                reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), 
                                                reinterpret_cast<const CryptoPP::byte*>(nonce.data()), nonce.size(), 
                                                aad, "", v.Tlen, false);
                             decryptSuccess = true;
                        } catch (...) {
                            decryptSuccess = false;
                        }

                        if (v.RESULT == "Pass") {
                            // Expect success and matching payload
                            if (decryptSuccess && pt_calc == expectedPayload) ok = true;
                        } else {
                            // Expect fail
                            if (!decryptSuccess) ok = true;
                        }
                        
                        if (ok) ++pass;
                        csv << name << "," << v.count << "," << (ok ? "1" : "0") << "\n";
                    }
                    else 
                    {
                        // VADT, VNT, VPT, VTT : Encryption Tests
                        // Input: Payload, Key, Nonce, AAD
                        // Output Check: CT
                        
                        std::string pt = HexToBytes(v.PAYLOAD);
                        if (v.Plen == 0) pt = "";

                        std::string ct_calc;
                        try {
                             std::string tagStr; // unused
                             ct_calc = AESEncrypt("CCM", pt, 
                                                reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size(), 
                                                reinterpret_cast<const CryptoPP::byte*>(nonce.data()), nonce.size(), 
                                                aad, tagStr, v.Tlen, false);
                        } catch(...) {
                            ct_calc = "";
                        }
                        
                        // Compare CT
                        if (BytesToHex(ct_calc) == v.CIPHERTEXT) ok = true;

                        if (ok) ++pass;
                        csv << name << "," << v.count << "," << (ok ? "1" : "0") << "\n";
                    }
                }
            }
            else if(mode == "GCM")
            {
                auto tests = ParseRsp_GCM(path);
                for (auto& v : tests) {
                    ++total;

                    std::string key = HexToBytes(v.Key);
                    std::string iv = HexToBytes(v.IV);
                    std::string aad = HexToBytes(v.AAD);
                    std::string pt = HexToBytes(v.PT);
                    std::string ct = HexToBytes(v.CT);
                    
                    int ivLen = (int)iv.size();

                    bool ok = false;

                    if (name.find("Encrypt") != std::string::npos) {
                        std::string tag_out_hex; 
                        std::string ct_calc = AESEncrypt("GCM", pt,
                            (const byte*)key.data(), (int)key.size(),
                            (const byte*)iv.data(), ivLen,
                            aad, tag_out_hex, v.tagLen, false);

                        ok = (BytesToHex(ct_calc) == v.CT) && (tag_out_hex == v.Tag);
                    }
                    else if (name.find("Decrypt") != std::string::npos) {
                        bool decryptSuccess = false;
                        std::string pt_calc;
                        
                        try {
                            pt_calc = AESDecrypt("GCM", ct,
                                reinterpret_cast<const CryptoPP::byte*>(key.data()), (int)key.size(),
                                reinterpret_cast<const CryptoPP::byte*>(iv.data()), ivLen,
                                aad, v.Tag, v.tagLen, false);
                            decryptSuccess = true;
                        } catch (...) {
                            decryptSuccess = false;
                        }

                        if (v.shouldFail) {
                            // Expected to fail - pass if decryption failed
                            ok = !decryptSuccess;
                        } else {
                            // Expected to succeed - pass if decryption succeeded and PT matches
                            ok = decryptSuccess && (BytesToHex(pt_calc) == v.PT);
                        }
                    }

                    if (ok) ++pass;
                    csv << name << "," << v.count << "," << (ok ? "1" : "0") << "\n";
                }
            }

            double rate = total ? 100.0 * pass / total : 0.0;
            std::cout << name << ": " << pass << "/" << total
                      << " (" << std::fixed << std::setprecision(2) << rate << "%)\n";

            totalAll += total;
            passAll += pass;
        }
        double overall = totalAll ? 100.0 * passAll / totalAll : 0.0;
    std::cout << "\nOverall: " << passAll << "/" << totalAll
              << " (" << std::fixed << std::setprecision(2) << overall << "%)\n";
    std::cout << "Results written to output/kat_results.csv\n";
}
}

void PrintHelp()
{
    std::cout << "\nUsage: AES_KAT [--kat] [--encrypt|--decrypt] [options]\n"
              << "Options:\n"
              << "  --mode <MODE>   AES mode: ECB,CBC,CFB,OFB,CTR,CCM,GCM,XTS\n"
              << "  --key <HEX>     Key in hex (16/24/32 bytes)\n"
              << "  --iv <HEX>      IV/nonce in hex (except ECB)\n"
              << "  --in <FILE>     Input file\n"
              << "  --out <FILE>    Output file\n"
              << "  --encode <FMT>  hex|base64|raw (default hex)\n"
              << "  --aad <HEX>     Additional data for AEAD\n"
              << "  --tag <HEX>     Auth tag for GCM decrypt\n"
              << "  --tagSize <N>   Tag size in bits (CCM/GCM)\n"
              << "  --verbose       Show details\n"
              << "\nExamples:\n"
              << "  AES_KAT --kat\n"
              << "  AES_KAT --encrypt --mode CBC --key ... --iv ... --in f.txt --out f.enc\n"
              << std::endl;
}
// ./AES_KAT --kat ...
#if !defined(BENCHMARK_SKIP_MAIN) && !defined(CATCH_SKIP_MAIN)
int main(int argc, char* argv[]) // chưa thêm iv len
{
    std::string mode, inputText, keyHex, ivHex, outputFile, encode = "hex", tag = "", aad = "", tagSize = ""; // keyHex is tweak value input hex or tweak value input dataUnitSeq of XTS
    bool kat = false, encrypt = false, decrypt = false, verbose = false;

    for(int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];
        if(arg == "--help") {PrintHelp(); return 0;}
        else if(arg == "--kat") {RunKat(); return 0;} 
        else if(arg == "--mode" && i+1 < argc) mode = argv[++i]; 
        else if (arg == "--encrypt") encrypt = true;
        else if (arg == "--decrypt") decrypt = true;
        else if(arg == "--in" && i+1 < argc) inputText = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outputFile = argv[++i];
        else if (arg == "--key" && i + 1 < argc) keyHex = argv[++i];
        else if (arg == "--iv" && i + 1 < argc) ivHex = argv[++i];
        else if (arg == "--encode" && i + 1 < argc) encode = argv[++i];
        else if(arg == "--aad"&& i + 1 < argc) aad = argv[++i];
        else if(arg == "--tag"&& i + 1 < argc) tag = argv[++i];
        else if(arg == "--tagSize"&& +1 < argc) tagSize = argv[++i];
        else if (arg == "--verbose") verbose = true;
    }

    if(!encrypt && !decrypt)
    {
        std::cerr << "Error: must specify --encrypt or --decrypt\n";
        PrintHelp();
        return 1;
    }
    if(mode != "ECB")
    {
    if (keyHex.empty() || ivHex.empty()) {
        std::cerr << "Error: missing key or iv(or data Unit Seq of XTS, or NOUNCE of CTR, CCM, GCM)\n";
        return 1;
    }
    }
    else
    {
        if (keyHex.empty()) {
        std::cerr << "Error: missing key\n";
        return 1;
    }
    }
    

    std::string keyBytes = HexToBytes(keyHex);
    std::string ivBytes  = HexToBytes(ivHex);
    size_t ivLen = ivBytes.size();
    size_t tagLen;
    // if(mode == "CCM") {
    //     if(encrypt)
    //     {
    //         tagLen = std::stoi(tagSize);
    //     }
    //     else 
            tagLen = static_cast<size_t>(std::stoi(tagSize));
        // }

    std::string plainBytes = HexToBytes(inputText);

    // if (mode == "CFB" || mode == "OFB" || mode == "CTR" || mode == "GCM")
    // {
    //     // Nếu chỉ 1 ký tự và là 0 hoặc 1 -> chuẩn hóa về dạng hex hợp lệ
    //     if (inputText == "0")
    //         plainBytes = HexToBytes("00");
    //     else if (inputText == "1")
    //         plainBytes = HexToBytes("01");
    //     else
    //         plainBytes = HexToBytes(inputText); // bình thường
    // }
    // else
    // {
    //     // Các mode block cần đủ 16 bytes
    //     plainBytes = HexToBytes(inputText);
    // }

    
    // if(mode == "XTS" || mode == "GCM")
    // {
    // }
    // else if(mode == "ECB")
    // {
    //     if((keyBytes.size() != 16 && keyBytes.size() != 24 && keyBytes.size() != 32))
    // {
    //     std::cerr << "Error: invalid key length\n"
    //                 "KEY length: 16 || 24 || 32 bytes\n";
    //     return 1;
    // }
    // }
    // else
    // {
    //     if((keyBytes.size() != 16 && keyBytes.size() != 24 && keyBytes.size() != 32) || (ivBytes.size() != CryptoPP::AES::BLOCKSIZE))
    //     {
    //         std::cerr << "Error: invalid key/IV length\n"
    //                     "KEY length: 16 || 24 || 32 bytes\n"
    //                     "IV length: 16 bytes expected\n";
    //         return 1;
    //     }
    // }

    std::string result;
    try 
    {
        if( mode == "ECB") // Add warning in this mode
        {
            std::cout << "WARNING!!\n"
                        "This mode is not secure!!\n"
                        "Do you want to use it? (type ""1"" to use)\n";
            size_t choose = 0;
            std::cin >> choose;
            if(choose == 1)
            {
                if(encrypt)
                {
                    if(verbose)
                    {
                        std::cout << "[+] Encrypt mode\n"
                          << "[+] Input text: " << inputText << "\n"
                          << "[+] Key: " << keyHex << "\n";
                    }

                    result = AESEncrypt(mode, plainBytes, 
                                        reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                        NULL, ivLen, aad, tag, tagLen, true);

                    if (encode == "base64") result = BytesToBase64(result);
                    else if (encode == "hex") result = BytesToHex(result);
                    else if (encode != "raw") throw std::runtime_error("Invalid encode type");

                    if (verbose) std::cout << "[+] Ciphertext (" << encode << "): " << result << "\n";
                }
                else
                {
                    if(verbose)
                    {
                        std::cout << "[+] Decrypt mode\n"
                          << "[+] Input text: " << inputText << "\n"
                          << "[+] Key: " << keyHex << "\n";
                    }

                    std::string cipherBytes;
                    if (encode == "base64") cipherBytes = Base64ToBytes(inputText);
                    else if (encode == "hex") cipherBytes = HexToBytes(inputText);
                    else cipherBytes = inputText;
                    

                    result = AESDecrypt(mode, cipherBytes , 
                                        reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                        NULL, ivLen, aad, tag, 0, true);

                    if (verbose) std::cout << "[+] Plaintext (" << encode << "): " << result << "\n";
                }
            }
            else
            {
                return 1;
            }
        }
        else if(mode == "XTS" || mode == "CBC" || mode == "OFB" || mode == "CFB" || mode == "CTR") // Tweak value input will be processing in RunKat(), default tweak is hex
        {
            if(encrypt)
            {
                if(verbose)
                {
                    std::cout << "[+] Encrypt mode\n"
                        << "[+] Input text: " << inputText << "\n"
                        << "[+] Key: " << keyHex << "\n"
                        << "[+] IV: " << ivHex << "\n";
                }

                if(mode == "CBC")
                {
                result = AESEncrypt(mode, plainBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, true);
                }
                else if(mode == "CFB")
                {
                    if(inputText == "1" || inputText == "0")
                    {
                        result = AESEncrypt(mode, inputText, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, true);
                        
                        if (verbose) std::cout << "[+] Ciphertext: " << result << "\n";
                        return 0;
                    }
                    else
                        result = AESEncrypt(mode, plainBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, false);
                }
                else
                {
                result = AESEncrypt(mode, plainBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, false);
                }


                if (encode == "base64") result = BytesToBase64(result);
                else if (encode == "hex") result = BytesToHex(result);
                else if (encode != "raw") throw std::runtime_error("Invalid encode type");

                if (verbose) std::cout << "[+] Ciphertext (" << encode << "): " << result << "\n";
            }
            else
            {
                if(verbose)
                {
                    std::cout << "[+] Decrypt mode\n"
                        << "[+] Input text: " << inputText << "\n"
                        << "[+] Key: " << keyHex << "\n"
                        << "[+] IV: " << ivHex << "\n";
                }

                std::string cipherBytes;
                if (encode == "base64") cipherBytes = Base64ToBytes(inputText);
                else if (encode == "hex") cipherBytes = HexToBytes(inputText);
                else cipherBytes = inputText;

                if(mode == "CBC")
                {
                result = AESDecrypt(mode, cipherBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, true);
                }
                else if(mode == "CFB")
                {
                    if(inputText == "1" || inputText == "0")
                    {
                        result = AESDecrypt(mode, inputText, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, true);
                        
                        if (verbose) std::cout << "[+] Plaintext: "<< result << "\n";
                        return 0;
                    }
                    else
                    {
                    result = AESDecrypt(mode, plainBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, false);
                    }
                }
                else
                {
                result = AESDecrypt(mode, cipherBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, 0, false);
                }

                result = BytesToHex(result);
                if (verbose) std::cout << "[+] Plaintext (" << encode << "): " << result << "\n";
            }
        }    
        else if(mode == "GCM" || mode == "CCM")
        {

            if(encrypt)
            {
                if(verbose)
                {
                    std::cout << "[+] Encrypt mode\n"
                        << "[+] Input text: " << inputText << "\n"
                        << "[+] Key: " << keyHex << "\n"
                        << "[+] IV: " << ivHex << "\n";
                }

                result = AESEncrypt(mode, plainBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, tagLen, false);
                
                if (encode == "base64") result = BytesToBase64(result);
                else if (encode == "hex") result = BytesToHex(result);
                else if (encode != "raw") throw std::runtime_error("Invalid encode type");

                if (verbose) 
                {
                    std::cout << "[+] Ciphertext (" << encode << "): " << result << "\n";
                    if(mode == "GCM")
                    {
                        std::cout << "[+] Tag: " << tag << "\n";
                    }
                }
            }
            else
            {
                if(verbose)
                {
                    std::cout << "[+] Decrypt mode\n"
                        << "[+] Input text: " << inputText << "\n"
                        << "[+] Key: " << keyHex << "\n"
                        << "[+] IV:  " << ivHex << "\n";
                }

                std::string cipherBytes;
                if (encode == "base64") cipherBytes = Base64ToBytes(inputText);
                else if (encode == "hex") cipherBytes = HexToBytes(inputText);
                else cipherBytes = inputText;

                result = AESDecrypt(mode, cipherBytes, 
                                    reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()), keyBytes.size(), 
                                    reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()), ivLen, aad, tag, tagLen, false);

                if (verbose) 
                {
                    std::cout << "[+] Plaintext (" << encode << "): " << result << "\n";
                    if(mode == "GCM")
                    {
                        std::cout << "[+] Tag: " << tag << "\n";
                    }
                }
            }
        }
    }
    catch (const CryptoPP::Exception& e) 
    {
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
#endif
