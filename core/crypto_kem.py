import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from umbral import SecretKey, PublicKey, encrypt, decrypt_original

# 1. Load persistent identities from disk
t0 = time.perf_counter()
with open("keys/hospital_a.sk", "rb") as f:
    sk_a = SecretKey.from_bytes(f.read())
with open("keys/hospital_a.pk", "rb") as f:
    pk_a = PublicKey.from_bytes(f.read())
with open("keys/doctor_b.sk", "rb") as f:
    sk_b = SecretKey.from_bytes(f.read())

t_load = (time.perf_counter() - t0) * 1000
print(f"Hospital A PK: {bytes(pk_a).hex()[:16]}... ({t_load:.1f}ms)")

# 2. Ingest persistent DEM key
key_file = "payloads/k_aes.raw"
if os.path.exists(key_file):
    with open(key_file, "rb") as f:
        k_aes = f.read()
else:
    k_aes = AESGCM.generate_key(bit_length=256)

assert len(k_aes) == 32
print(f"Target: {k_aes.hex()[:16]}... (32B)")

# 3. Hospital A encapsulates
t0 = time.perf_counter()
capsule, envelope = encrypt(pk_a, k_aes)
t_enc = (time.perf_counter() - t0) * 1000

cap_bytes = bytes(capsule)
print(f"Capsule: {t_enc:.1f}ms ({len(cap_bytes)}B)")
print(f"Envelope: {len(envelope)}B ciphertext")

# Persist artifacts for downstream steps
with open("payloads/capsule.bin", "wb") as f:
    f.write(cap_bytes)

with open("payloads/envelope.bin", "wb") as f:
    f.write(envelope)

# 4. Hospital A direct decapsulation check
t0 = time.perf_counter()
recovered = decrypt_original(sk_a, capsule, envelope)
print(f"Decapsulate: {(time.perf_counter() - t0)*1000:.1f}ms")

assert recovered == k_aes
print("Baseline: Key match")

# 5. Doctor B isolation check
try:
    decrypt_original(sk_b, capsule, envelope)
    print("Isolation: Test failed")
except Exception:
    print("Isolation: Doctor locked")