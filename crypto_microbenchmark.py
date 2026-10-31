#!/usr/bin/env python3
"""Controlled AES-256-GCM/SHA-256 microbenchmark for synthetic medical-file payloads.

This is an isolated cryptographic-processing experiment. It does NOT invoke
PCRIM/BC-HealthCare, IPFS, Ethereum, or a live patient-data workflow.
"""
import argparse, csv, json, os, platform, statistics, time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

SIZES = [64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 10 * 1024 * 1024]
REPEATS = 30
WARMUPS = 3
BATCH_SIZE = 20


def summarize(values):
    ordered = sorted(values)
    q1 = statistics.median(ordered[:len(ordered)//2])
    q3 = statistics.median(ordered[(len(ordered)+1)//2:])
    return {
        "mean_ms": statistics.mean(values),
        "stdev_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
        "median_ms": statistics.median(values),
        "q1_ms": q1,
        "q3_ms": q3,
        "min_ms": min(values),
        "max_ms": max(values),
    }


def timed(fn):
    wall0 = time.perf_counter_ns()
    cpu0 = time.process_time_ns()
    result = fn()
    cpu = (time.process_time_ns() - cpu0) / 1e6
    wall = (time.perf_counter_ns() - wall0) / 1e6
    return result, wall, cpu


def run(outdir: Path, repeats: int):
    outdir.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    aes = AESGCM(key)
    rows = []
    integrity_rows = []
    raw_samples = {}
    for size in SIZES:
        payload = os.urandom(size)  # synthetic, non-identifying data
        enc_wall, dec_wall, hash_wall = [], [], []
        enc_cpu, dec_cpu, hash_cpu = [], [], []
        ciphertext_len = None
        # Warm-up batches are excluded from statistics. Each sample times a batch
        # and divides by BATCH_SIZE to reduce timer-resolution noise.
        def encrypt_one():
            nonce = os.urandom(12)  # fresh 96-bit nonce for every encryption
            return nonce, aes.encrypt(nonce, payload, None)
        def decrypt_one(item):
            nonce, ct = item
            return aes.decrypt(nonce, ct, None)
        def hash_one():
            h = hashes.Hash(hashes.SHA256()); h.update(payload); return h.finalize()
        for _ in range(WARMUPS):
            for __ in range(BATCH_SIZE):
                item = encrypt_one(); recovered = decrypt_one(item); digest = hash_one()
        for _ in range(repeats):
            encrypted_batch, ew, ec = timed(lambda: [encrypt_one() for __ in range(BATCH_SIZE)])
            recovered_batch, dw, dc = timed(lambda: [decrypt_one(item) for item in encrypted_batch])
            digest_batch, hw, hc = timed(lambda: [hash_one() for __ in range(BATCH_SIZE)])
            if any(recovered != payload for recovered in recovered_batch):
                raise RuntimeError("AES-GCM round-trip mismatch")
            if any(len(digest) != 32 for digest in digest_batch):
                raise RuntimeError("Unexpected SHA-256 digest length")
            enc_wall.append(ew / BATCH_SIZE); dec_wall.append(dw / BATCH_SIZE); hash_wall.append(hw / BATCH_SIZE)
            enc_cpu.append(ec / BATCH_SIZE); dec_cpu.append(dc / BATCH_SIZE); hash_cpu.append(hc / BATCH_SIZE)
            ciphertext_len = len(encrypted_batch[-1][1])
        # AES-GCM output includes 16-byte authentication tag; nonce is stored separately.
        # Payload ciphertext length therefore adds 16 bytes; nonce adds another 12 bytes.
        overhead_bytes = 12 + 16
        row = {
            "payload_bytes": size,
            "payload_mib": size / (1024 * 1024),
            "ciphertext_plus_nonce_bytes": size + overhead_bytes,
            "overhead_bytes": overhead_bytes,
            "overhead_percent": overhead_bytes / size * 100,
        }
        for name, vals in [("encrypt", enc_wall), ("decrypt", dec_wall), ("sha256", hash_wall)]:
            stats = summarize(vals)
            for k, v in stats.items(): row[f"{name}_{k}"] = v
            row[f"{name}_throughput_mib_s"] = (size / (1024 * 1024)) / (stats["mean_ms"] / 1000)
        for name, vals in [("encrypt_cpu", enc_cpu), ("decrypt_cpu", dec_cpu), ("sha256_cpu", hash_cpu)]:
            row[f"{name}_mean_ms"] = statistics.mean(vals)
        rows.append(row)
        raw_samples[str(size)] = {"encrypt_ms_per_op": enc_wall, "decrypt_ms_per_op": dec_wall, "sha256_ms_per_op": hash_wall}
        # One tampering test per size: flip a bit and require AES-GCM authentication failure.
        nonce2 = os.urandom(12)
        # Build a ciphertext with a known nonce, then tamper its authentication tag.
        valid = aes.encrypt(nonce2, payload, None)
        tampered = bytearray(valid); tampered[-1] ^= 1
        rejected = False
        try:
            aes.decrypt(nonce2, bytes(tampered), None)
        except Exception as exc:
            rejected = exc.__class__.__name__ == "InvalidTag"
        if not rejected:
            raise RuntimeError("Tampered ciphertext was not rejected")
        integrity_rows.append({"payload_bytes": size, "tampered_ciphertext_rejected": rejected})

    fields = list(rows[0].keys())
    with (outdir / "crypto_benchmark_results.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields); w.writeheader(); w.writerows(rows)
    with (outdir / "integrity_test_results.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(integrity_rows[0].keys())); w.writeheader(); w.writerows(integrity_rows)
    meta = {
        "experiment": "AES-256-GCM encryption/decryption and SHA-256 hashing microbenchmark",
        "scope": "isolated local cryptographic microbenchmark; not integrated with PCRIM, IPFS, or Ethereum",
        "payloads": "synthetic random bytes; no real patient data",
        "repetitions_per_size": repeats,
        "warmup_batches_per_size": WARMUPS,
        "operations_per_timed_sample": BATCH_SIZE,
        "sizes_bytes": SIZES,
        "aes": "AES-256-GCM; fresh 96-bit nonce for each encryption; 128-bit authentication tag",
        "hash": "SHA-256",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cryptography_package": __import__("cryptography").__version__,
        "cpu_logical_count": os.cpu_count(),
        "key_handling": "one ephemeral random key generated once for this benchmark run; not persisted",
        "cpu_model_reported_by_host": "Intel Xeon Platinum 8573C; container exposes 3 logical CPUs",
        "limitations": [
            "does not measure IPFS upload/download, Ethereum transactions, gas, or application end-to-end latency",
            "does not validate the encryption/key-management implementation in the published repositories",
            "results are specific to this execution environment and should not be generalized to production servers"
        ]
    }
    (outdir / "experiment_metadata.json").write_text(json.dumps(meta, indent=2))
    (outdir / "raw_samples.json").write_text(json.dumps(raw_samples, indent=2))
    print(json.dumps({"metadata": meta, "results": rows, "integrity": integrity_rows}, indent=2))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results", help="output directory")
    ap.add_argument("--repeats", type=int, default=REPEATS)
    args = ap.parse_args()
    run(Path(args.out), args.repeats)
