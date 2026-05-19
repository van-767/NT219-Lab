// AES-128 (FIPS-197) + CTR mode
// No external crypto libraries. Single-file demo with KATs.

#include <bits/stdc++.h>
using namespace std;

using u8  = uint8_t;
using u32 = uint32_t;
using Bytes = vector<u8>;

static const int Nb = 4; // block size in 32-bit words (constant)
static const int Nk = 4; // key length in 32-bit words for AES-128
static const int Nr = 10; // number of rounds for AES-128

// ---------- S-box and inverse S-box ----------
static const u8 sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const u8 inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

// Round constant
static const u32 Rcon[11] = {
    0x00000000u,
    0x01000000u,0x02000000u,0x04000000u,0x08000000u,
    0x10000000u,0x20000000u,0x40000000u,0x80000000u,
    0x1b000000u,0x36000000u
};

// Helpers: hex <-> bytes
static uint8_t hex_to_nybble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    throw runtime_error("Invalid hex char");
}
Bytes HexToBytes(const string &hex) {
    string h = hex;
    if (h.size() % 2) throw runtime_error("Hex length must be even");
    Bytes out; out.reserve(h.size()/2);
    for (size_t i=0;i<h.size();i+=2) {
        u8 hi = hex_to_nybble(h[i]);
        u8 lo = hex_to_nybble(h[i+1]);
        out.push_back((hi<<4) | lo);
    }
    return out;
}
string BytesToHex(const Bytes &b) {
    static const char* hexchars = "0123456789abcdef";
    string s; s.reserve(b.size()*2);
    for (u8 x : b) {
        s.push_back(hexchars[x>>4]);
        s.push_back(hexchars[x & 0xF]);
    }
    return s;
}

// XOR in place: a ^= b (b must be same length)
void xor_inplace(Bytes &a, const Bytes &b) {
    for (size_t i=0;i<a.size();++i) a[i] ^= b[i];
}

static void loadState(const u8 *block, u8 state[4][4]) {
    for (int col=0; col<4; ++col)
        for (int row=0; row<4; ++row)
            state[row][col] = block[col*4 + row];
}

static void storeState(const u8 state[4][4], u8 *block) {
    for (int col=0; col<4; ++col)
        for (int row=0; row<4; ++row)
            block[col*4 + row] = state[row][col];
}


// ---------- AES core ----------
// State is 16 bytes in column-major order: state[col*4 + row]
struct AES {
    // Expanded key schedule: 4*(Nr+1) 32-bit words -> (Nb*(Nr+1)) words, but easier: 4*(Nr+1) words for AES-128 is 44 words.
    u32 w[4*(Nr+1)]; // 44 words

    AES(const Bytes &key) {
        if (key.size() != 16) throw runtime_error("Only AES-128 supported in this implementation (16-byte key).");
        key_expansion(key);
    }

    static u32 to_u32_be(const u8 b[4]) {
        return (u32(b[0])<<24) | (u32(b[1])<<16) | (u32(b[2])<<8) | u32(b[3]);
    }
    static void from_u32_be(u32 x, u8 out[4]) {
        out[0] = (x>>24) & 0xFF;
        out[1] = (x>>16) & 0xFF;
        out[2] = (x>>8) & 0xFF;
        out[3] = x & 0xFF;
    }

    void key_expansion(const Bytes &key) {
        // key: 16 bytes
        // w[0..Nk-1] from key
        for (int i=0;i<Nk;i++) {
            u8 tmp[4] = { key[4*i], key[4*i+1], key[4*i+2], key[4*i+3] };
            w[i] = to_u32_be(tmp);
        }
        for (int i=Nk;i < Nb*(Nr+1); ++i) {
            u32 temp = w[i-1];
            if (i % Nk == 0) {
                // RotWord + SubWord + Rcon
                u8 tbytes[4];
                from_u32_be(temp, tbytes);
                // RotWord
                u8 rot[4] = { tbytes[1], tbytes[2], tbytes[3], tbytes[0] };
                // SubWord
                for (int j=0;j<4;++j) rot[j] = sbox[rot[j]];
                u32 subw = to_u32_be(rot);
                temp = subw ^ Rcon[i/Nk];
            }
            w[i] = w[i-Nk] ^ temp;
        }
    }

    // Basic AES operations on state (16 bytes)
    static void SubBytes(u8 state[4][4]) {
        for(int r=0;r<4;r++)
            for(int c=0;c<4;c++)
                state[r][c] = sbox[state[r][c]];
    }

    static void InvSubBytes(u8 state[4][4]) {
        for(int r=0;r<4;r++)
            for(int c=0;c<4;c++)
                state[r][c] = inv_sbox[state[r][c]];
    }

   static void ShiftRows(u8 state[4][4]) {
        u8 tmp[4];
        // row 1
        tmp[0] = state[1][0]; tmp[1] = state[1][1]; tmp[2] = state[1][2]; tmp[3] = state[1][3];
        state[1][0] = tmp[1]; state[1][1] = tmp[2]; state[1][2] = tmp[3]; state[1][3] = tmp[0];
        // row 2
        tmp[0] = state[2][0]; tmp[1] = state[2][1]; tmp[2] = state[2][2]; tmp[3] = state[2][3];
        state[2][0] = tmp[2]; state[2][1] = tmp[3]; state[2][2] = tmp[0]; state[2][3] = tmp[1];
        // row 3
        tmp[0] = state[3][0]; tmp[1] = state[3][1]; tmp[2] = state[3][2]; tmp[3] = state[3][3];
        state[3][0] = tmp[3]; state[3][1] = tmp[0]; state[3][2] = tmp[1]; state[3][3] = tmp[2];
    }

    static void InvShiftRows(u8 state[4][4]) {
        u8 tmp[4];
        // row 1
        tmp[0] = state[1][0]; tmp[1] = state[1][1]; tmp[2] = state[1][2]; tmp[3] = state[1][3];
        state[1][0] = tmp[3]; state[1][1] = tmp[0]; state[1][2] = tmp[1]; state[1][3] = tmp[2];
        // row 2
        tmp[0] = state[2][0]; tmp[1] = state[2][1]; tmp[2] = state[2][2]; tmp[3] = state[2][3];
        state[2][0] = tmp[2]; state[2][1] = tmp[3]; state[2][2] = tmp[0]; state[2][3] = tmp[1];
        // row 3
        tmp[0] = state[3][0]; tmp[1] = state[3][1]; tmp[2] = state[3][2]; tmp[3] = state[3][3];
        state[3][0] = tmp[1]; state[3][1] = tmp[2]; state[3][2] = tmp[3]; state[3][3] = tmp[0];
    }


    // xtime = multiply by {02} in GF(2^8)
    static inline u8 xtime(u8 x) {
        return (u8)((x << 1) ^ ( (x & 0x80) ? 0x1b : 0x00 ));
    }
    static u8 mul(u8 a, u8 b) {
        // generic GF(2^8) multiply (could be optimized)
        u8 res = 0;
        u8 tmp = a;
        for (int i=0;i<8;i++) {
            if (b & (1<<i)) res ^= tmp;
            tmp = xtime(tmp);
        }
        return res;
    }

    static void MixColumns(u8 state[4][4]) {
        for(int c=0;c<4;c++) {
            u8 a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
            state[0][c] = mul(0x02,a0) ^ mul(0x03,a1) ^ a2 ^ a3;
            state[1][c] = a0 ^ mul(0x02,a1) ^ mul(0x03,a2) ^ a3;
            state[2][c] = a0 ^ a1 ^ mul(0x02,a2) ^ mul(0x03,a3);
            state[3][c] = mul(0x03,a0) ^ a1 ^ a2 ^ mul(0x02,a3);
        }
    }

    static void InvMixColumns(u8 state[4][4]) {
        for(int c=0;c<4;c++) {
            u8 a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
            state[0][c] = mul(0x0e,a0) ^ mul(0x0b,a1) ^ mul(0x0d,a2) ^ mul(0x09,a3);
            state[1][c] = mul(0x09,a0) ^ mul(0x0e,a1) ^ mul(0x0b,a2) ^ mul(0x0d,a3);
            state[2][c] = mul(0x0d,a0) ^ mul(0x09,a1) ^ mul(0x0e,a2) ^ mul(0x0b,a3);
            state[3][c] = mul(0x0b,a0) ^ mul(0x0d,a1) ^ mul(0x09,a2) ^ mul(0x0e,a3);
        }
    }



    static void AddRoundKey(u8 state[4][4], const u32 w[44], int round) {
    for(int c=0;c<4;c++){
        u32 rk = w[round*4 + c];
        state[0][c] ^= (rk >> 24) & 0xFF;
        state[1][c] ^= (rk >> 16) & 0xFF;
        state[2][c] ^= (rk >> 8) & 0xFF;
        state[3][c] ^= rk & 0xFF;
    }
}

    void encrypt_block(const u8 in[16], u8 out[16]) const {
    u8 state[4][4];
    loadState(in, state);

    AddRoundKey(state, w, 0);
        for(int r=1;r<Nr;r++){
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, w, r);
        }
        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, w, Nr);

        storeState(state, out);
    }

    void decrypt_block(const u8 in[16], u8 out[16]) const {
        u8 state[4][4];
        loadState(in, state);

        AddRoundKey(state, w, Nr);
        for(int r=Nr-1;r>=1;r--){
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, w, r);
            InvMixColumns(state);
        }
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, w, 0);

        storeState(state, out);
    }
};

// ==================== CTR MODE ====================
void increment_counter(u8 counter[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

Bytes aes_ctr_crypt(const AES &aes, const Bytes &iv, const Bytes &data) {
    if (iv.size() != 16) throw runtime_error("IV/Counter must be 16 bytes");
    Bytes out; out.reserve(data.size());
    
    u8 counter[16];
    for (int i = 0; i < 16; ++i) counter[i] = iv[i];
    
    u8 keystream[16];
    for (size_t i = 0; i < data.size(); i += 16) {
        aes.encrypt_block(counter, keystream);
        
        size_t block_size = min((size_t)16, data.size() - i);
        for (size_t j = 0; j < block_size; ++j) {
            out.push_back(data[i+j] ^ keystream[j]);
        }
        
        increment_counter(counter);
    }
    return out;
}
// ---------- Tests (KATs) ----------

void load16(const Bytes &b, u8 out[16]) {
    for(int i=0;i<16;i++) out[i] = b[i];
}

bool testFip(const string &filename) {
    ifstream fin(filename);
    if(!fin) { cerr << "Cannot open file\n"; return false; }

    string line;
    Bytes plaintext, key, ciphertext, inv_ciphertext;
    while(getline(fin, line)) {
        // Xóa trailing space/r/n
        while(!line.empty() && isspace(line.back())) line.pop_back();

        if(line.find("PLAINTEXT:") != string::npos) {
            plaintext = HexToBytes(line.substr(line.find(":")+2));
        } else if(line.find("KEY:") != string::npos) {
            key = HexToBytes(line.substr(line.find(":")+2));
        } else if(line.find("round[10].output") != string::npos) {
            ciphertext = HexToBytes(line.substr(line.find_last_of(' ')+1));
        } else if(line.find("ioutput") != string::npos) {
            inv_ciphertext = HexToBytes(line.substr(line.find_last_of(' ')+1));
        }
    }

    if(plaintext.empty() || key.empty() || ciphertext.empty() || inv_ciphertext.empty()) {
        cerr << "Error parsing FIP file\n";
        return false;
    }

    AES aes(key);

    u8 enc_out[16], dec_out[16];
    load16(plaintext, enc_out);
    aes.encrypt_block(enc_out, enc_out);

    load16(ciphertext, dec_out);
    aes.decrypt_block(dec_out, dec_out);

    // Kiểm tra encrypt
    bool enc_ok = true;
    for(int i=0;i<16;i++) if(enc_out[i] != ciphertext[i]) enc_ok=false;

    // Kiểm tra decrypt
    bool dec_ok = true;
    for(int i=0;i<16;i++) if(dec_out[i] != plaintext[i]) dec_ok=false;

    cout << "[+] Test 1: FIPS-197 Appendix C.1 (Block Cipher)\n";
    cout << "    - Key       : " << BytesToHex(key) << "\n";
    cout << "    - Plaintext : " << BytesToHex(plaintext) << "\n";
    cout << "    - Expected  : " << BytesToHex(ciphertext) << "\n";
    cout << "    -> Encrypt Result: " << (enc_ok ? "PASS" : "FAIL") << "\n";
    cout << "    -> Decrypt Result: " << (dec_ok ? "PASS" : "FAIL") << "\n\n";

    if(!enc_ok) {
        cout << "      [!] Got Encrypt: " << BytesToHex(Bytes(enc_out, enc_out+16)) << "\n";
    }
    if(!dec_ok) {
        cout << "      [!] Got Decrypt: " << BytesToHex(Bytes(dec_out, dec_out+16)) << "\n";
    }
    return enc_ok && dec_ok;
}


bool testCTR_SP800_38A() {
    string plain_hex =
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52ef"
        "f69f2445df4f9b17ad2b417be66c3710";
    string cipher_hex =
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff"
        "5ae4df3edbd5d35e5b4f09020db03eab"
        "1e031dda2fbe03d1792170a0f3009cee";

    Bytes plaintext = HexToBytes(plain_hex);
    Bytes expected_cipher = HexToBytes(cipher_hex);
    Bytes key = HexToBytes("2b7e151628aed2a6abf7158809cf4f3c");
    Bytes counter = HexToBytes("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    
    AES aes(key);

    // --- CTR Encrypt ---
    Bytes enc_out = aes_ctr_crypt(aes, counter, plaintext);
    
    // --- CTR Decrypt ---
    Bytes dec_out = aes_ctr_crypt(aes, counter, enc_out);

    // --- Kiểm tra kết quả ---
    bool pass_enc = (enc_out == expected_cipher);
    bool pass_dec = (dec_out == plaintext);

    cout << "[+] Test 2: NIST SP 800-38A F.5.1 (CTR Mode - 4 Blocks)\n";
    cout << "    - Key       : " << BytesToHex(key) << "\n";
    cout << "    - Counter   : " << BytesToHex(counter) << "\n";
    cout << "    - Plaintext : " << BytesToHex(plaintext).substr(0, 32) << "... (" << plaintext.size() << " bytes)\n";
    cout << "    - Expected  : " << BytesToHex(expected_cipher).substr(0, 32) << "... (" << expected_cipher.size() << " bytes)\n";
    cout << "    -> Encrypt Result: " << (pass_enc ? "PASS" : "FAIL") << "\n";
    cout << "    -> Decrypt Result: " << (pass_dec ? "PASS" : "FAIL") << "\n\n";

    if(!pass_enc) {
        cout << "      [!] Got Encrypt: " << BytesToHex(enc_out) << "\n";
    }

    return pass_enc && pass_dec;
}


Bytes randomKey(size_t size = 16)
{
    std::random_device rd;
    std::mt19937_64 rng(rd());
    Bytes key(size);

    for (size_t i = 0; i < size; ++i)
        key[i] = rng() & 0xFF;

    return key;
}

Bytes randomIV(size_t size = 16)
{
    std::random_device rd;
    std::mt19937_64 rng(rd());
    Bytes IV(size);

    for (size_t i = 0; i < size; ++i)
        IV[i] = rng() & 0xFF;

    return IV;
}

string ReadFile(const string& path)
{
    ifstream file(path, ios::binary | ios::ate); // ate -> đưa con trỏ xuống cuối cùng
    if(!file.is_open())
    {
        throw runtime_error("Can't open file " + path);
    }

    streamsize size = file.tellg(); // size = con trỏ hiện tại(cuối file)
    file.seekg(0, ios::beg);

    vector<unsigned char> buffer(size);

    file.read(reinterpret_cast<char*>(buffer.data()), size);
    if (file.gcount() != size) {
        throw runtime_error("File read error: " + path);
    }
    file.close();

    ostringstream oss;
    oss << hex << setfill('0');
    for (unsigned char byte : buffer) {
        oss << setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

void runKat() {
    cout << "========================================\n";
    cout << "   AES-128 KAT (Known Answer Tests)\n";
    cout << "========================================\n\n";
    
    bool t1 = testFip("fips_197.txt");
    bool t2 = testCTR_SP800_38A();
    
    cout << "========================================\n";
    cout << "Overall KAT result: " << (t1 && t2 ? "ALL PASSED" : "SOME FAILED") << "\n";
    cout << "========================================\n";
}

// Parse command line args
map<string, string> ParseArgs(int argc, char* argv[]) {
    map<string, string> args;
    for (int i = 1; i < argc - 1; i++) {
        string key = argv[i];
        if (key.rfind("--", 0) == 0) {
            args[key.substr(2)] = argv[i + 1];
        }
    }
    return args;
}
void runBenchmark() {
    const vector<size_t> sizes = {1024, 4096, 16384, 262144, 1048576, 8388608};
    const vector<string> names = {"1KiB", "4KiB", "16KiB", "256KiB", "1MiB", "8MiB"};
    
    Bytes key = randomKey(16);
    Bytes iv(16, 0); 
    
    AES aes(key);
    const int warm = 2, reps = 1000, runs = 30;

    cout << "Benchmarking AES-128 CTR...\n";

    // Mở file CSV
    #ifdef _WIN32
    system("mkdir output\\windows 2> nul");
    ofstream csv("output/windows/benchmark_ctr.csv");
    #else
    system("mkdir -p output/linux");
    ofstream csv("output/linux/benchmark_ctr.csv");
    #endif
    csv << "Mode,InputSize,Operation,Run,Time(s),Throughput(MB/s)\n";

    for (size_t s = 0; s < sizes.size(); ++s) {
        cout << "--- Size: " << names[s] << " ---" << endl;
        Bytes plain(sizes[s], 0xAA);
        Bytes ct_fixed = aes_ctr_crypt(aes, iv, plain);
        
        // ================= ENCRYPT =================
        for (int w = 0; w < warm; ++w) {
            Bytes ct = aes_ctr_crypt(aes, iv, plain);
        }
        
        vector<double> latencies_enc;
        long long total_core_us_enc = 0;
        auto overall_start_enc = chrono::high_resolution_clock::now();
        
        for (int r = 0; r < runs; ++r) {
            auto t0 = chrono::high_resolution_clock::now();
            for (int i = 0; i < reps; ++i) {
                Bytes ct = aes_ctr_crypt(aes, iv, plain);
            }
            auto t1 = chrono::high_resolution_clock::now();
            long long us = chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
            total_core_us_enc += us;
            double sec_per_op = us / 1'000'000'000.0;
            latencies_enc.push_back(sec_per_op);
            
            double throughput = (sizes[s] / (1024.0 * 1024.0)) / sec_per_op;
            csv << "CTR," << names[s] << ",Encrypt," << r << "," << sec_per_op << "," << throughput << "\n";
        }
        
        auto overall_end_enc = chrono::high_resolution_clock::now();
        auto dur_ms_enc = chrono::duration_cast<chrono::milliseconds>(overall_end_enc - overall_start_enc).count();
        double total_ms_enc = total_core_us_enc / 1000.0;
        double avg_ms_enc = total_ms_enc / (double)runs;

        double mean_lat_enc = accumulate(latencies_enc.begin(), latencies_enc.end(), 0.0) / latencies_enc.size();
        double throughput_enc = (sizes[s] / (1024.0 * 1024.0)) / mean_lat_enc;
        
        cout << "[Encrypt]\n";
        cout << "  - Total elapsed time: " << dur_ms_enc << " ms\n";
        cout << "  - Total core time   : " << fixed << setprecision(6) << total_ms_enc << " ms\n";
        cout << "  - Average core time : " << fixed << setprecision(6) << avg_ms_enc << " ms\n";
        cout << "  - Average latency   : " << mean_lat_enc * 1e6 << " us/op\n";
        cout << "  - Throughput        : " << throughput_enc << " MB/s\n";

        // ================= DECRYPT =================
        for (int w = 0; w < warm; ++w) {
            Bytes pt = aes_ctr_crypt(aes, iv, ct_fixed);
        }
        
        vector<double> latencies_dec;
        long long total_core_us_dec = 0;
        auto overall_start_dec = chrono::high_resolution_clock::now();

        for (int r = 0; r < runs; ++r) {
            auto t0 = chrono::high_resolution_clock::now();
            for (int i = 0; i < reps; ++i) {
                Bytes pt = aes_ctr_crypt(aes, iv, ct_fixed);
            }
            auto t1 = chrono::high_resolution_clock::now();
            long long us = chrono::duration_cast<chrono::microseconds>(t1 - t0).count();
            total_core_us_dec += us;
            double sec_per_op = us / 1'000'000'000.0;
            latencies_dec.push_back(sec_per_op);
            
            double throughput = (sizes[s] / (1024.0 * 1024.0)) / sec_per_op;
            csv << "CTR," << names[s] << ",Decrypt," << r << "," << sec_per_op << "," << throughput << "\n";
        }
        auto overall_end_dec = chrono::high_resolution_clock::now();
        auto dur_ms_dec = chrono::duration_cast<chrono::milliseconds>(overall_end_dec - overall_start_dec).count();
        double total_ms_dec = total_core_us_dec / 1000.0;
        double avg_ms_dec = total_ms_dec / (double)runs;

        double mean_lat_dec = accumulate(latencies_dec.begin(), latencies_dec.end(), 0.0) / latencies_dec.size();
        double throughput_dec = (sizes[s] / (1024.0 * 1024.0)) / mean_lat_dec;
        
        cout << "[Decrypt]\n";
        cout << "  - Total elapsed time: " << dur_ms_dec << " ms\n";
        cout << "  - Total core time   : " << fixed << setprecision(6) << total_ms_dec << " ms\n";
        cout << "  - Average core time : " << fixed << setprecision(6) << avg_ms_dec << " ms\n";
        cout << "  - Average latency   : " << mean_lat_dec * 1e6 << " us/op\n";
        cout << "  - Throughput        : " << throughput_dec << " MB/s\n\n";
    }
    csv.close();
}
// Hàm in hướng dẫn sử dụng
void printHelp() {
    cout << "Usage: ctr_mode --mode <kat|benchmark|encrypt|decrypt> [options]\n\n"
         << "  --mode kat            Run Known Answer Tests\n"
         << "  --mode benchmark      Run performance benchmark\n"
         << "  --mode encrypt        Encrypt data\n"
         << "  --mode decrypt        Decrypt data\n\n"
         << "Options for encrypt/decrypt:\n"
         << "  --key <hex>           AES-128 key (32 hex chars, optional)\n"
         << "  --iv  <hex>           Initial counter / IV (32 hex chars, optional)\n"
         << "  --input <hex>         Plaintext or ciphertext in hex (required)\n";
}
// ---------- main ----------
int main(int argc, char* argv[]) {
    // Tăng tốc nhập/xuất (không ảnh hưởng đến kết quả)
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    // Parse tham số dòng lệnh -> map<string, string>
    map<string, string> args = ParseArgs(argc, argv);

    // Nếu không có --mode, in hướng dẫn và thoát
    if (args.find("mode") == args.end()) {
        printHelp();
        return 0;
    }

    string mode = args["mode"];

    // ==================== KAT ====================
    if (mode == "kat") {
        runKat();
    }
    // ==================== BENCHMARK ====================
    else if (mode == "benchmark") {
        runBenchmark();
    }
    // ==================== ENCRYPT / DECRYPT ====================
    else if (mode == "encrypt" || mode == "decrypt") {

        // Lấy tham số, nếu thiếu key hoặc iv thì tự sinh
        string inputHex = args["input"];
        string keyHex   = args["key"];
        string ivHex    = args["iv"];

        // --- Tự sinh key (16 bytes = 32 hex chars) nếu chưa có ---
        if (keyHex.empty()) {
            Bytes newKey = randomKey(16);
            keyHex = BytesToHex(newKey);
            cout << "[+] Generated random key: " << keyHex << endl;
        }

        // --- Tự sinh IV (16 bytes = 32 hex chars) nếu chưa có ---
        if (ivHex.empty()) {
            Bytes newIV = randomIV(16);
            ivHex = BytesToHex(newIV);
            cout << "[+] Generated random IV : " << ivHex << endl;
        }

        // --- Input validation (Fail closed) ---
        // Kiểm tra độ dài key (32 hex) và IV (32 hex)
        if (keyHex.length() != 32) {
            cerr << "Error: key must be exactly 32 hex characters (16 bytes).\n";
            return 1;
        }
        if (ivHex.length() != 32) {
            cerr << "Error: IV must be exactly 32 hex characters (16 bytes).\n";
            return 1;
        }

        // Chuyển hex -> bytes, bắt lỗi ký tự hex không hợp lệ
        Bytes key, iv, in_data;
        try {
            key     = HexToBytes(keyHex);
            iv      = HexToBytes(ivHex);
            in_data = HexToBytes(inputHex);
        } catch (const exception& e) {
            cerr << "Error: invalid hex input (" << e.what() << ").\n";
            return 1;
        }

        // Tạo đối tượng AES với key đã nhập/tự sinh
        AES aes(key);

        // Thực hiện mã hóa hoặc giải mã (CTR dùng chung hàm)
        Bytes out_data = aes_ctr_crypt(aes, iv, in_data);

        // In kết quả
        if (mode == "encrypt") {
            cout << "AES-128 (FIPS-197) + CTR Mode\n";
            cout << "Cipher(hex): " << BytesToHex(out_data) << endl;
        } else {
            cout << "AES-128 (FIPS-197) + CTR Mode\n";
            cout << "Plain(hex) : " << BytesToHex(out_data) << endl;
        }
    }
    else {
        // Nếu mode không hợp lệ, in hướng dẫn
        printHelp();
    }

    return 0;
}

// ====================================================================
// EXPORT DLL CHO PYTHON GUI
// ====================================================================
#ifdef _WIN32
    #define CBC_API __declspec(dllexport)
#else
    #define CBC_API __attribute__((visibility("default")))
#endif

extern "C" CBC_API int AES_Process(const char* action_c, const char* key_hex, const char* iv_hex, const char* in_path, const char* out_path) {
    try {
        string action(action_c);
        Bytes key = HexToBytes(key_hex);
        Bytes iv = HexToBytes(iv_hex);
        AES aes(key);

        // Đọc trực tiếp byte từ file
        ifstream fin(in_path, ios::binary | ios::ate);
        if(!fin) return -1;
        size_t size = fin.tellg();
        fin.seekg(0, ios::beg);
        Bytes in_data(size);
        fin.read((char*)in_data.data(), size);
        fin.close();

        Bytes out_data = aes_ctr_crypt(aes, iv, in_data);

        // Ghi trực tiếp byte ra file
        ofstream fout(out_path, ios::binary);
        if(!fout) return -3;
        fout.write((const char*)out_data.data(), out_data.size());
        fout.close();

        return 0;
    } catch(...) {
        return -4; // Lỗi độ dài Key/IV sai
    }
}