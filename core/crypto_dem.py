import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

INPUT_FILE = "payloads/payload_heavy_100mb.bin"
ENCRYPTED_FILE = "payloads/payload_heavy_100mb.enc"

if not os.path.exists(INPUT_FILE):
    raise FileNotFoundError(f"Missing {INPUT_FILE}. Run setup_payloads.py first.")

# 1. Ephemeral key setup
k_aes = AESGCM.generate_key(bit_length=256)
nonce = os.urandom(12)
cipher = AESGCM(k_aes)

print(f"Key: {k_aes.hex()[:16]}... (32B)")
print(f"Nonce: {nonce.hex()} (12B)")

# 2. Ingest payload
with open(INPUT_FILE, "rb") as f:
    raw_payload = f.read()

size_mb = len(raw_payload) / (1024 * 1024)
print(f"Loaded: {size_mb:.0f}MB payload")

# 3. Bulk hardware encryption
t0 = time.perf_counter()
ciphertext = cipher.encrypt(nonce, raw_payload, None)
t_enc = (time.perf_counter() - t0) * 1000

enc_speed = size_mb / (t_enc / 1000)
tag_overhead = len(ciphertext) - len(raw_payload)

print(f"Encrypted: {t_enc:.1f}ms ({enc_speed:.0f}MB/s)")
print(f"GHASH tag: +{tag_overhead}B appended")

# Persist ciphertext
with open(ENCRYPTED_FILE, "wb") as f:
    f.write(nonce + ciphertext)

# Persist AES key for crypto_kem.py
with open("payloads/k_aes.raw", "wb") as f:
    f.write(k_aes)
# 4. Decryption & integrity verify
t0 = time.perf_counter()
recovered_payload = cipher.decrypt(nonce, ciphertext, None)
t_dec = (time.perf_counter() - t0) * 1000

dec_speed = size_mb / (t_dec / 1000)
assert recovered_payload == raw_payload

print(f"Decrypted: {t_dec:.1f}ms ({dec_speed:.0f}MB/s)")
print("Parity: 100% match")

# 5. Tamper verification
tampered = bytearray(ciphertext)
tampered[500_000] ^= 0xFF

try:
    cipher.decrypt(nonce, bytes(tampered), None)
    print("Tamper check failed.")
except InvalidTag:
    print("Tamper: Rejected instantly")