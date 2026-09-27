import os, time

PAYLOAD_DIR = "payloads"
LIGHT_BYTES = 100 * 1024
HEAVY_BYTES = 100 * 1024 * 1024
CHUNK = 1024 * 1024

def write_file(path: str, total: int):
    if os.path.exists(path) and os.path.getsize(path) == total:
        return 0.0
    written = 0
    t0 = time.perf_counter()
    with open(path, "wb") as f:
        while written < total:
            size = min(CHUNK, total - written)
            f.write(os.urandom(size))
            written += size
        f.flush()
        os.fsync(f.fileno())
    return (time.perf_counter() - t0) * 1000

def read_file(path: str):
    t0 = time.perf_counter()
    with open(path, "rb") as f:
        data = f.read()
    ms = (time.perf_counter() - t0) * 1000
    mb_s = (len(data) / (1024 * 1024)) / (ms / 1000) if ms > 0 else 0
    return ms, mb_s

os.makedirs(PAYLOAD_DIR, exist_ok=True)
p_light = os.path.join(PAYLOAD_DIR, "payload_light_100kb.bin")
p_heavy = os.path.join(PAYLOAD_DIR, "payload_heavy_100mb.bin")

write_file(p_light, LIGHT_BYTES)
r_light_ms, _ = read_file(p_light)
print("Light payload ready.")
print(f"Read: {r_light_ms:.1f}ms")

write_file(p_heavy, HEAVY_BYTES)
r_heavy_ms, r_heavy_spd = read_file(p_heavy)
print("Heavy payload ready.")
print(f"Read: {r_heavy_ms:.1f}ms")
print(f"Throughput: {r_heavy_spd:.0f}MB/s")