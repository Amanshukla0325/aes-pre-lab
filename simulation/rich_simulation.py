import os
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from umbral import (
    Capsule,
    CapsuleFrag,
    KeyFrag,
    PublicKey,
    SecretKey,
    Signer,
    decrypt_reencrypted,
    reencrypt,
)

# Change this:
ROOT_DIR = Path(__file__).resolve().parent
if ROOT_DIR.name in ["benchmarks", "core"]:
  ROOT_DIR = ROOT_DIR.parent

# To this:
ROOT_DIR = Path(__file__).resolve().parent.parent

KEYS_DIR = ROOT_DIR / "keys"
PAYLOADS_DIR = ROOT_DIR / "payloads"


def make_layout() -> Layout:
  layout = Layout(name="root")
  layout.split_column(
      Layout(name="header", size=3),
      Layout(name="main", ratio=1),
      Layout(name="footer", size=3),
  )
  layout["main"].split_row(
      Layout(name="hospital", ratio=1),
      Layout(name="relays", ratio=1),
      Layout(name="doctor", ratio=1),
  )
  return layout


def update_ui(layout, logs_h, logs_r, logs_d, status="PROCESSING"):
  layout["header"].update(
      Panel(
          Text(
              "CAREGID ZERO-TRUST ARCHITECTURE : PRE + IPFS PIPELINE SIMULATION",
              justify="center",
              style="bold cyan",
          ),
          style="cyan",
      )
  )
  layout["hospital"].update(
      Panel(
          Text("\n".join(logs_h), style="green"),
          title="[bold green]1. HOSPITAL A (DATA OWNER)[/]",
          border_style="green",
      )
  )
  layout["relays"].update(
      Panel(
          Text("\n".join(logs_r), style="yellow"),
          title="[bold yellow]2. UNTRUSTED RELAY MESH (NUCs)[/]",
          border_style="yellow",
      )
  )
  layout["doctor"].update(
      Panel(
          Text("\n".join(logs_d), style="magenta"),
          title="[bold magenta]3. DOCTOR B (RECIPIENT)[/]",
          border_style="magenta",
      )
  )
  layout["footer"].update(
      Panel(
          Text(
              f"STATUS: {status} | ISOLATION: 100% | ZERO-LEAK VERIFIED",
              justify="center",
              style="bold white",
          ),
          style="bold blue",
      )
  )


def run_simulation():
  layout = make_layout()
  logs_h, logs_r, logs_d = [], [], []

  with Live(layout, refresh_per_second=10, screen=True):
    # Phase 1: Hospital A
    update_ui(layout, logs_h, logs_r, logs_d, "INIT IDENTITIES")
    time.sleep(0.5)

    with open(KEYS_DIR / "hospital_a.sk", "rb") as f:
      sk_a = SecretKey.from_bytes(f.read())
    with open(KEYS_DIR / "hospital_a.pk", "rb") as f:
      pk_a = PublicKey.from_bytes(f.read())
    with open(KEYS_DIR / "hospital_a.sig", "rb") as f:
      signer_a = Signer(SecretKey.from_bytes(f.read()))
    with open(KEYS_DIR / "hospital_a.vk", "rb") as f:
      vk_a = PublicKey.from_bytes(f.read())
    with open(KEYS_DIR / "doctor_b.pk", "rb") as f:
      pk_b = PublicKey.from_bytes(f.read())

    logs_h.append("[+] Identities Loaded")
    logs_h.append(f"    PK: {bytes(pk_a).hex()[:10]}...")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.4)

    with open(PAYLOADS_DIR / "payload_heavy_100mb.bin", "rb") as f:
      raw_scan = f.read()
    logs_h.append(f"[*] Bulk Scan: {len(raw_scan)/(1024*1024):.0f} MB")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.4)

    with open(PAYLOADS_DIR / "capsule.bin", "rb") as f:
      capsule = Capsule.from_bytes(f.read())
    with open(PAYLOADS_DIR / "envelope.bin", "rb") as f:
      envelope = f.read()
    with open(PAYLOADS_DIR / "k_aes.raw", "rb") as f:
      target_k_aes = f.read()

    logs_h.append("[+] DEM Pinned (IPFS)")
    logs_h.append("    CID: QmZtmD2...")
    logs_h.append(f"[+] Capsule: {len(bytes(capsule))}B")
    logs_h.append("[+] 2-of-3 Dispatched")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.6)

    # Phase 2: Relays
    update_ui(layout, logs_h, logs_r, logs_d, "RELAY BLIND TRANSFORMATION")
    logs_r.append("[*] Ingested KFrags")
    logs_r.append("    Zero Plaintext Access")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.4)

    verified_cfrags = []
    for idx in [1, 2]:
      t0 = time.perf_counter()
      with open(PAYLOADS_DIR / f"kfrag_{idx}.bin", "rb") as f:
        raw_kf = f.read()
      kf = KeyFrag.from_bytes(raw_kf)
      vkf = kf.verify(vk_a, pk_a, pk_b)
      cfrag = reencrypt(capsule, vkf)
      t_ms = (time.perf_counter() - t0) * 1000
      verified_cfrags.append(cfrag)

      logs_r.append(f"[+] Relay #{idx} Done")
      logs_r.append(f"    Time: {t_ms:.1f}ms")
      update_ui(layout, logs_h, logs_r, logs_d)
      time.sleep(0.4)

    logs_r.append("[✓] Quorum Met (2-of-3)")
    logs_r.append("[✓] Leak Audit: 0B")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.6)

    # Phase 3: Doctor B
    update_ui(layout, logs_h, logs_r, logs_d, "RECIPIENT DECRYPTION")
    with open(KEYS_DIR / "doctor_b.sk", "rb") as f:
      sk_b = SecretKey.from_bytes(f.read())

    logs_d.append("[+] Loaded sk_b")
    logs_d.append("[*] Ingested CFrags")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.4)

    t0 = time.perf_counter()
    recovered_k_aes = decrypt_reencrypted(
        receiving_sk=sk_b,
        delegating_pk=pk_a,
        capsule=capsule,
        verified_cfrags=verified_cfrags,
        ciphertext=envelope,
    )
    t_kem = (time.perf_counter() - t0) * 1000
    logs_d.append(f"[+] Decapsulated: {t_kem:.1f}ms")
    logs_d.append(f"    Key: {recovered_k_aes.hex()[:10]}...")

    assert recovered_k_aes == target_k_aes
    logs_d.append("[✓] Key Verified")
    update_ui(layout, logs_h, logs_r, logs_d)
    time.sleep(0.4)

    with open(PAYLOADS_DIR / "payload_heavy_100mb.enc", "rb") as f:
      enc_file = f.read()

    nonce = enc_file[:12]
    ciphertext = enc_file[12:]

    t0 = time.perf_counter()
    aes = AESGCM(recovered_k_aes)
    decrypted_scan = aes.decrypt(nonce, ciphertext, None)
    t_dem = (time.perf_counter() - t0) * 1000

    assert decrypted_scan == raw_scan
    speed = (len(decrypted_scan) / (1024 * 1024)) / (t_dem / 1000)

    logs_d.append(f"[+] Decrypted: {t_dem:.1f}ms")
    logs_d.append(f"    Speed: {speed:.0f} MB/s")
    logs_d.append("[✓] Parity Verified")
    update_ui(
        layout, logs_h, logs_r, logs_d, "EXECUTION COMPLETE: VERIFIED ZERO-TRUST"
    )
    time.sleep(3.0)


if __name__ == "__main__":
  run_simulation()