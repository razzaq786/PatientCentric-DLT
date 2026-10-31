# SmartHealthChain supplementary cryptographic experiment

## What was actually executed

A local controlled microbenchmark was executed in the ChatGPT analysis container using Python 3.13.5 and `cryptography` 46.0.4. It processed synthetic random payloads of 64 KiB, 256 KiB, 1 MiB, 4 MiB, and 10 MiB. For each size it collected 30 timed samples, each sample consisting of 20 AES-256-GCM encryptions, 20 decryptions, and 20 SHA-256 hashes, after three warm-up batches. Each encryption used a fresh 96-bit nonce. The benchmark also flipped one bit in the authentication tag for each payload size and confirmed that AES-GCM rejected all five modified ciphertexts.

## Important scope limitation

This is a real, executed local cryptographic microbenchmark, but it is **not** an end-to-end experiment on PCRIM, Ethereum, Ganache, or IPFS. The public source inspected for PCRIM/BC-HealthCare did not expose encryption/decryption in the medical-file upload path. Thus the measured AES-256-GCM operation is a candidate cryptographic stage, not a claim about the current application. Do not use these results to claim that the published prototype already encrypts files.

## Files

- `crypto_microbenchmark.py`: reproducible benchmark script.
- `results/crypto_benchmark_results.csv`: measured per-size statistics.
- `results/raw_samples.json`: raw 30-sample timing observations per size and operation.
- `results/integrity_test_results.csv`: five tampering checks (all rejected).
- `results/experiment_metadata.json`: environment and configuration.
- `section4_crypto_microbenchmark.tex`: insertion-ready Section 4 subsection and results table.
- `replace_section3_encryption_claim.tex`: replacement for overclaiming encryption/access-control text in Section 3.

## Reproduce

```bash
python -m pip install cryptography==46.0.4
python crypto_microbenchmark.py --out results --repeats 30
```

The absolute timings may vary across machines. Re-run on the target experimental server if the paper is to report that server's performance. Do not combine these values with Figure 3 application measurements.
