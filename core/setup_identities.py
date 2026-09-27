import os
import time
from umbral import SecretKey, Signer

KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def write_key(path: str, data: bytes):
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(data)

t0 = time.perf_counter()

# 1. Hospital A identities (Encryption + Signing)
sk_a = SecretKey.random()
pk_a = sk_a.public_key()

signer_a_sk = SecretKey.random()
signer_a = Signer(signer_a_sk)
vk_a = signer_a.verifying_key()

# 2. Doctor B identities (Encryption only)
sk_b = SecretKey.random()
pk_b = sk_b.public_key()

# 3. Persist raw bytes
write_key(os.path.join(KEYS_DIR, "hospital_a.sk"), sk_a.to_secret_bytes())
write_key(os.path.join(KEYS_DIR, "hospital_a.pk"), bytes(pk_a))
write_key(os.path.join(KEYS_DIR, "hospital_a.sig"), signer_a_sk.to_secret_bytes())
write_key(os.path.join(KEYS_DIR, "hospital_a.vk"), bytes(vk_a))

write_key(os.path.join(KEYS_DIR, "doctor_b.sk"), sk_b.to_secret_bytes())
write_key(os.path.join(KEYS_DIR, "doctor_b.pk"), bytes(pk_b))

print(f"Identities: {(time.perf_counter() - t0)*1000:.1f}ms")
print("Keys stored safely.")
