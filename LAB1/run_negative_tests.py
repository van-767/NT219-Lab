import os
import subprocess

def run_cmd(cmd):
    print(f"> {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[FAIL CLOSED] Error caught: {result.stderr.strip()}")
    else:
        print(f"[SUCCESS] Command completed.")
    print("-" * 50)
    return result.returncode

def flip_byte(filename):
    with open(filename, "rb") as f:
        data = bytearray(f.read())
    # Đổi bit của byte đầu tiên
    data[0] ^= 0xFF
    with open(filename, "wb") as f:
        f.write(data)

def write_hex(filename, hex_str):
    with open(filename, "w") as f:
        f.write(hex_str)

print("=" * 50)
print("LAB 1 - NEGATIVE TESTS DEMONSTRATION")
print("=" * 50)

# Chuẩn bị dữ liệu chuẩn
write_hex("msg.txt", "Plaintext for testing negative cases.")
run_cmd("AES_benchmark.exe genKeyIV CBC 16 Hex key_valid.hex iv_valid.hex")
run_cmd("AES_benchmark.exe encrypt CBC Hex key_valid.hex iv_valid.hex Hex 1KiB.bin cipher_cbc.bin")

run_cmd("AES_benchmark.exe genKeyIV GCM 16 Hex key_gcm.hex iv_gcm.hex")
run_cmd("AES_benchmark.exe encrypt GCM Hex key_gcm.hex iv_gcm.hex Hex 1KiB.bin cipher_gcm.bin --tagSize 16")

# 1. Wrong key
print("\n[TEST 1] Wrong key -> incorrect plaintext (or failure)")
write_hex("key_wrong.hex", "00" * 16)
run_cmd("AES_benchmark.exe decrypt CBC Hex key_wrong.hex iv_valid.hex Hex cipher_cbc.bin recovered_wrong_key.bin")

# 2. Wrong IV
print("\n[TEST 2] Wrong IV -> incorrect plaintext")
write_hex("iv_wrong.hex", "00" * 16)
run_cmd("AES_benchmark.exe decrypt CBC Hex key_valid.hex iv_wrong.hex Hex cipher_cbc.bin recovered_wrong_iv.bin")

# 3. Tampered ciphertext (non-AEAD) -> corrupted output
print("\n[TEST 3] Tampered ciphertext (CBC) -> corrupted output")
# Copy cipher_cbc.bin to cipher_cbc_tampered.bin and flip a byte
with open("cipher_cbc.bin", "rb") as f_in, open("cipher_cbc_tampered.bin", "wb") as f_out:
    f_out.write(f_in.read())
flip_byte("cipher_cbc_tampered.bin")
run_cmd("AES_benchmark.exe decrypt CBC Hex key_valid.hex iv_valid.hex Hex cipher_cbc_tampered.bin recovered_tampered.bin")

# 4 & 5. Tampered ciphertext/tag (AEAD) -> authentication failure
print("\n[TEST 4 & 5] Tampered ciphertext (GCM) -> authentication failure (Fail Closed)")
with open("cipher_gcm.bin", "rb") as f_in, open("cipher_gcm_tampered.bin", "wb") as f_out:
    f_out.write(f_in.read())
flip_byte("cipher_gcm_tampered.bin")
run_cmd("AES_benchmark.exe decrypt GCM Hex key_gcm.hex iv_gcm.hex Hex cipher_gcm_tampered.bin recovered_gcm.bin --tagSize 16")

# 6. Invalid IV length -> rejection
print("\n[TEST 6] Invalid IV length -> rejection")
write_hex("iv_short.hex", "0102030405") # 5 bytes only
run_cmd("AES_benchmark.exe encrypt CBC Hex key_valid.hex iv_short.hex Hex 1KiB.bin cipher_test.bin")
