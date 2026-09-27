import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from umbral import (
    SecretKey,
    PublicKey,
    Capsule,
    CapsuleFrag,
    decrypt_reencrypted,
)

# 1. Load keys and artifacts
t0 = time.perf_counter()

with open("keys/doctor_b.sk", "rb") as f:
    sk_b = SecretKey.from_bytes(f.read())
with open("keys/doctor_b.pk", "rb") as f:
    pk_b = PublicKey.from_bytes(f.read())
with open("keys/hospital_a.pk", "rb") as f:
    pk_a = PublicKey.from_bytes(f.read())
with open("keys/hospital_a.vk", "rb") as f:
    vk_a = PublicKey.from_bytes(f.read())

with open("payloads/capsule.bin", "rb") as f:
    capsule = Capsule.from_bytes(f.read())
with open("payloads/envelope.bin", "rb") as f:
    envelope = f.read()

# Load and verify CFrags (2-of-3 threshold)
cfrags = []
for i in [1, 2]:
    with open(f"payloads/cfrag_{i}.bin", "rb") as f:
        raw_cf = f.read()
    cfrag = CapsuleFrag.from_bytes(raw_cf)
    verified_cf = cfrag.verify(capsule, verifying_pk=vk_a, delegating_pk=pk_a, receiving_pk=pk_b)
    cfrags.append(verified_cf)

t_load = (time.perf_counter() - t0) * 1000
print(f"Loaded inputs: {t_load:.1f}ms")

# 2. Lagrange decapsulation
t0 = time.perf_counter()
recovered_k_aes = decrypt_reencrypted(
    receiving_sk=sk_b,
    delegating_pk=pk_a,
    capsule=capsule,
    verified_cfrags=cfrags,
    ciphertext=envelope,
)
t_kem = (time.perf_counter() - t0) * 1000

print(f"Decapsulated: {t_kem:.1f}ms")
print(f"Recovered: {recovered_k_aes.hex()[:16]}...")

# Target parity check
with open("payloads/k_aes.raw", "rb") as f:
    target_k_aes = f.read()

assert recovered_k_aes == target_k_aes
print("KEM match: 100% verified")

# 3. Bulk DEM decryption
with open("payloads/payload_heavy_100mb.enc", "rb") as f:
    enc_data = f.read()

nonce = enc_data[:12]
ciphertext_with_tag = enc_data[12:]

t0 = time.perf_counter()
aes = AESGCM(recovered_k_aes)
decrypted_data = aes.decrypt(nonce, ciphertext_with_tag, None)
t_dem = (time.perf_counter() - t0) * 1000

size_mb = len(decrypted_data) / (1024 * 1024)
dem_speed = size_mb / (t_dem / 1000)

print(f"Bulk DEM: {t_dem:.1f}ms ({dem_speed:.0f}MB/s)")

# 4. End-to-end parity
with open("payloads/payload_heavy_100mb.bin", "rb") as f:
    original_data = f.read()

assert decrypted_data == original_data
print("DEM parity: 100% match")