import os, time
from umbral import (
    SecretKey, Signer, PublicKey, KeyFrag, Capsule,
    encrypt, decrypt_original, generate_kfrags, reencrypt, decrypt_reencrypted
)

# 1. Clean key generation
sk_a = SecretKey.random()
pk_a = sk_a.public_key()
signer_a = Signer(SecretKey.random())
vk_a = signer_a.verifying_key()

sk_b = SecretKey.random()
pk_b = sk_b.public_key()

# 2. Hospital A encapsulates
key = os.urandom(32)
t0 = time.perf_counter()
capsule, envelope = encrypt(pk_a, key)
print(f"Capsule: {(time.perf_counter() - t0)*1000:.1f}ms")

# Baseline check
assert decrypt_original(sk_a, capsule, envelope) == key
print("Baseline check passed.")

# 3. Delegate to Hospital B
t0 = time.perf_counter()
kfrags = generate_kfrags(sk_a, pk_b, signer_a, 2, 3)
print(f"Delegation: {(time.perf_counter() - t0)*1000:.1f}ms")

# 4. Relays transform wire bytes
cfrags = []
vk_a_b = bytes(vk_a)
pk_a_b = bytes(pk_a)
pk_b_b = bytes(pk_b)
cap_b = bytes(capsule)

for idx in range(2):
    t0 = time.perf_counter()
    raw_kf = bytes(kfrags[idx])
    parsed_kf = KeyFrag.from_bytes(raw_kf)
    verified_kf = parsed_kf.verify(
        PublicKey.from_bytes(vk_a_b),
        PublicKey.from_bytes(pk_a_b),
        PublicKey.from_bytes(pk_b_b)
    )
    cf = reencrypt(Capsule.from_bytes(cap_b), verified_kf)
    cfrags.append(cf)
    print(f"Relay {idx+1}: {(time.perf_counter() - t0)*1000:.1f}ms")

# 5. Hospital B recovers key
t0 = time.perf_counter()
recovered = decrypt_reencrypted(sk_b, pk_a, capsule, cfrags, envelope)
print(f"Decapsulation: {(time.perf_counter() - t0)*1000:.1f}ms")

assert recovered == key
print("Integrity verified.")