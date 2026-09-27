import os
import time
from umbral import (
    SecretKey,
    PublicKey,
    Signer,
    generate_kfrags,
    KeyFrag,
    VerifiedKeyFrag,
)

# 1. Load keys
t0 = time.perf_counter()
with open("keys/hospital_a.sk", "rb") as f:
    sk_a = SecretKey.from_bytes(f.read())
with open("keys/hospital_a.pk", "rb") as f:
    pk_a = PublicKey.from_bytes(f.read())
with open("keys/hospital_a.sig", "rb") as f:
    signer_a = Signer(SecretKey.from_bytes(f.read()))
with open("keys/doctor_b.pk", "rb") as f:
    pk_b = PublicKey.from_bytes(f.read())

vk_a = signer_a.verifying_key()
t_load = (time.perf_counter() - t0) * 1000

print(f"Identities: {t_load:.1f}ms")
print(f"A: {bytes(pk_a).hex()[:8]}...")
print(f"B: {bytes(pk_b).hex()[:8]}...")

# 2. Delegation math
THRESHOLD = 2
SHARES = 3

t0 = time.perf_counter()
kfrags = generate_kfrags(
    delegating_sk=sk_a,
    receiving_pk=pk_b,
    signer=signer_a,
    threshold=THRESHOLD,
    shares=SHARES,
)
t_gen = (time.perf_counter() - t0) * 1000

print(f"Policy: {THRESHOLD}-of-{SHARES}")
print(f"Generated: {t_gen:.1f}ms")

# 3. Persist shares
serialized = [bytes(kf) for kf in kfrags]
size_b = len(serialized[0])

for idx, raw in enumerate(serialized, start=1):
    with open(f"payloads/kfrag_{idx}.bin", "wb") as f:
        f.write(raw)

print(f"Share: {size_b}B")
print(f"Saved: {SHARES} files")

# 4. Relay verification
for idx, raw in enumerate(serialized, start=1):
    kf = KeyFrag.from_bytes(raw)
    vkf = kf.verify(
        verifying_pk=vk_a,
        delegating_pk=pk_a,
        receiving_pk=pk_b,
    )
    assert isinstance(vkf, VerifiedKeyFrag)

print("Relays: All verified")

# 5. Zero-leak audit
sk_a_bytes = sk_a.to_secret_bytes()
for raw in serialized:
    assert sk_a_bytes not in raw

print("Leak: Zero detected")