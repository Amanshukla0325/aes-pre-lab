import os
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from umbral import (
    SecretKey,
    PublicKey,
    Signer,
    KeyFrag,
    encrypt,
    generate_kfrags,
    reencrypt,
    decrypt_reencrypted,
)

# 1. Resolve paths relative to project root
ROOT_DIR = Path(__file__).resolve().parent.parent
KEYS_DIR = ROOT_DIR / "keys"
PAYLOADS_DIR = ROOT_DIR / "payloads"

with open(KEYS_DIR / "hospital_a.sk", "rb") as f:
    sk_a = SecretKey.from_bytes(f.read())
with open(KEYS_DIR / "hospital_a.pk", "rb") as f:
    pk_a = PublicKey.from_bytes(f.read())
with open(KEYS_DIR / "hospital_a.sig", "rb") as f:
    signer_a = Signer(SecretKey.from_bytes(f.read()))
with open(KEYS_DIR / "hospital_a.vk", "rb") as f:
    vk_a = PublicKey.from_bytes(f.read())
with open(KEYS_DIR / "doctor_b.sk", "rb") as f:
    sk_b = SecretKey.from_bytes(f.read())
with open(KEYS_DIR / "doctor_b.pk", "rb") as f:
    pk_b = PublicKey.from_bytes(f.read())

RUNS = [
    ("100 KB", PAYLOADS_DIR / "payload_light_100kb.bin"),
    ("100 MB", PAYLOADS_DIR / "payload_heavy_100mb.bin"),
]

benchmarks = []

for label, path in RUNS:
    with open(path, "rb") as f:
        data = f.read()

    # 1. Bulk DEM Encrypt
    k_aes = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    cipher = AESGCM(k_aes)
    
    t0 = time.perf_counter_ns()
    ct = cipher.encrypt(nonce, data, None)
    t_dem_enc = (time.perf_counter_ns() - t0) / 1_000_000

    # 2. KEM Encapsulate
    t0 = time.perf_counter_ns()
    capsule, envelope = encrypt(pk_a, k_aes)
    t_kem_enc = (time.perf_counter_ns() - t0) / 1_000_000

    # 3. Delegation (2-of-3)
    t0 = time.perf_counter_ns()
    kfrags = generate_kfrags(
        delegating_sk=sk_a,
        receiving_pk=pk_b,
        signer=signer_a,
        threshold=2,
        shares=3,
    )
    t_del = (time.perf_counter_ns() - t0) / 1_000_000

    # 4. Relay Blind Re-encryption (2 Relays)
    verified_kfrags = [
        KeyFrag.from_bytes(bytes(kf)).verify(vk_a, pk_a, pk_b)
        for kf in kfrags[:2]
    ]
    t0 = time.perf_counter_ns()
    # reencrypt directly returns VerifiedCapsuleFrag
    verified_cfrags = [reencrypt(capsule, vkf) for vkf in verified_kfrags]
    t_relay = (time.perf_counter_ns() - t0) / 1_000_000

    # 5. KEM Decapsulate
    t0 = time.perf_counter_ns()
    rec_k_aes = decrypt_reencrypted(
        receiving_sk=sk_b,
        delegating_pk=pk_a,
        capsule=capsule,
        verified_cfrags=verified_cfrags,
        ciphertext=envelope,
    )
    t_kem_dec = (time.perf_counter_ns() - t0) / 1_000_000
    assert rec_k_aes == k_aes

    # 6. Bulk DEM Decrypt
    t0 = time.perf_counter_ns()
    rec_data = cipher.decrypt(nonce, ct, None)
    t_dem_dec = (time.perf_counter_ns() - t0) / 1_000_000
    assert rec_data == data

    benchmarks.append({
        "label": label,
        "dem_enc": t_dem_enc,
        "kem_enc": t_kem_enc,
        "delegation": t_del,
        "relay": t_relay,
        "kem_dec": t_kem_dec,
        "dem_dec": t_dem_dec,
    })

# Format terminal table
print("\n" + "=" * 70)
print(f"{'Operation':<26} | {'100 KB':<12} | {'100 MB':<12} | {'Scaling':<10}")
print("-" * 70)
metrics = [
    ("dem_enc", "Bulk DEM Encrypt"),
    ("kem_enc", "KEM Encapsulate"),
    ("delegation", "KFrag Delegation"),
    ("relay", "Relay Re-encryption"),
    ("kem_dec", "KEM Decapsulate"),
    ("dem_dec", "Bulk DEM Decrypt"),
]

for key, name in metrics:
    v_light = benchmarks[0][key]
    v_heavy = benchmarks[1][key]
    scaling = f"{v_heavy / v_light:.2f}x" if v_light > 0 else "N/A"
    print(f"{name:<26} | {v_light:>9.2f} ms | {v_heavy:>9.2f} ms | {scaling:>10}")
print("=" * 70)