import os
import sys
import subprocess
import streamlit as st

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

st.set_page_config(page_title="CareGrid AES-PRE Lab", layout="wide")
st.title("CareGrid: Zero-Trust Medical Study Re-Encryption")
st.caption("Interactive Pipeline Runner & Artifact Inspector")

# Ensure directories exist
os.makedirs("keys", exist_ok=True)
os.makedirs("payloads", exist_ok=True)

def run_script(script_path: str):
    # sys.executable ensures the script runs in the active virtual environment
    res = subprocess.run(
        [sys.executable, os.path.join(ROOT_DIR, script_path)],
        capture_output=True,
        text=True,
        cwd=ROOT_DIR,
    )
    if res.returncode == 0:
        st.success(f"`{script_path}` executed successfully.")
        st.code(res.stdout, language="text")
    else:
        st.error(f"Error executing `{script_path}`:")
        st.code(res.stderr, language="text")

def get_file_info(path: str):
    if os.path.exists(path):
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            sample = f.read(24).hex()
        return f"{size:,} B", f"{sample}..."
    return "Not generated", "—"

# Two-column layout: Controls on the left, Artifact Inspector on the right
ctrl_col, view_col = st.columns([1, 1.2])

with ctrl_col:
    st.subheader("1. Setup")
    if st.button("Step 0: Generate Identities (setup_identities.py)"):
        run_script("core/setup_identities.py")

    st.subheader("2. Hospital Edge Node (Origin)")
    if st.button("Step 1A: Setup Payloads (setup_payloads.py)"):
        run_script("core/setup_payloads.py")

    if st.button("Step 1B: Bulk DEM Lock (crypto_dem.py)"):
        run_script("core/crypto_dem.py")

    if st.button("Step 1C: Capsule KEM Lock (crypto_kem.py)"):
        run_script("core/crypto_kem.py")

    if st.button("Step 1D: Slice Delegation Bridge (crypto_delegation.py)"):
        run_script("core/crypto_delegation.py")

    st.subheader("3. Untrusted Relays")
    if st.button("Step 2: Run Relay Transformation (crypto_relay.py)"):
        run_script("core/crypto_relay.py")

    st.subheader("4. Recipient Node (Doctor B)")
    if st.button("Step 3: Decrypt & Verify (crypto_dec.py)"):
        run_script("core/crypto_dec.py")

with view_col:
    st.subheader("Disk Artifacts Inspector (`payloads/`)")
    tracked_files = [
        "payloads/payload_heavy_100mb.bin",
        "payloads/payload_heavy_100mb.enc",
        "payloads/k_aes.raw",
        "payloads/capsule.bin",
        "payloads/envelope.bin",
        "payloads/kfrag_1.bin",
        "payloads/kfrag_2.bin",
        "payloads/kfrag_3.bin",
        "payloads/cfrag_1.bin",
        "payloads/cfrag_2.bin",
    ]
    table_rows = []
    for filepath in tracked_files:
        size, sample = get_file_info(filepath)
        table_rows.append({"File": filepath, "Size on Disk": size, "Hex Preview": sample})
    st.table(table_rows)

    st.subheader("Identity Keys (`keys/`)")
    key_files = [
        "keys/hospital_a.pk",
        "keys/hospital_a.vk",
        "keys/doctor_b.pk",
        "keys/doctor_b.sk",
    ]
    key_rows = []
    for k in key_files:
        size, sample = get_file_info(k)
        key_rows.append({"Key File": k, "Status": "Present" if os.path.exists(k) else "Missing"})
    st.table(key_rows)