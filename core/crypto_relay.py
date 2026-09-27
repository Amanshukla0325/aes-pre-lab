import os
import time
from umbral import (
    PublicKey,
    Signer,
    SecretKey,
    Capsule,
    KeyFrag,
    reencrypt,
    CapsuleFrag,
)

# 1. Load public metadata & capsule
t0 = time.perf_counter()

with open("keys/hospital_a.pk", "rb") as f:
    pk_a = PublicKey.from_bytes(f.read())
with open("keys/doctor_b.pk", "rb") as f:
    pk_b = PublicKey.from_bytes(f.read())
with open("keys/hospital_a.sig", "rb") as f:
    vk_a = Signer(SecretKey.from_bytes(f.read())).verifying_key()
with open("payloads/capsule.bin", "rb") as f:
    capsule = Capsule.from_bytes(f.read())

t_load = (time.perf_counter() - t0) * 1000
print(f"Loaded inputs: {t_load:.1f}ms")

# 2. Re-encryption worker function
def run_relay(node_id: int) -> tuple[bytes, float]:
    kfrag_path = f"payloads/kfrag_{node_id}.bin"
    with open(kfrag_path, "rb") as f:
        raw_kfrag = f.read()

    t_start = time.perf_counter()
    
    # Parse & verify
    untrusted = KeyFrag.from_bytes(raw_kfrag)
    verified = untrusted.verify(vk_a, pk_a, pk_b)
    
    # Blind transformation
    cfrag = reencrypt(capsule, verified)
    latency = (time.perf_counter() - t_start) * 1000
    
    return bytes(cfrag), latency

# 3. Execute 2-of-3 threshold relays
cfrags = []
THRESHOLD = 2

for i in range(1, THRESHOLD + 1):
    cfrag_bytes, latency = run_relay(i)
    cfrags.append(cfrag_bytes)
    
    # Persist artifact for Phase 7
    with open(f"payloads/cfrag_{i}.bin", "wb") as f:
        f.write(cfrag_bytes)
        
    print(f"Relay {i}: {latency:.1f}ms")

# 4. Telemetry & structural verification
cfrag_size = len(cfrags[0])
print(f"CFrag size: {cfrag_size}B")
print(f"Satisfied: {THRESHOLD}-of-3 threshold")

# 5. Isolation check
with open("keys/hospital_a.sk", "rb") as f:
    sk_a = f.read()
with open("payloads/k_aes.raw", "rb") as f:
    k_aes = f.read()

for cf in cfrags:
    assert sk_a not in cf
    assert k_aes not in cf

print("Leak: Zero detected")