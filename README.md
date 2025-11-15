# BYOK Demo: Kyber (PQC) vs RSA

This demo compares a Kyber-based BYOK (bring-your-own-key) flow to an RSA-based BYOK flow. It measures:

- key generation time
- encapsulation/encryption time (protecting symmetric data key)
- decapsulation/decryption time (recovering symmetric key)
- symmetric data encryption time (AES-GCM)
- key and ciphertext sizes

Prerequisites
- Python 3.9+
- Install dependencies from `requirements.txt`:

```powershell
pip install -r requirements.txt
```

Usage

- Run both experiments and produce `results.json`:

```powershell
python .\run_experiments.py --iterations 30 --kyber-variant kyber768 --rsa-key-size 2048 --out results.json
```

- Produce plots from `results.json`:

```powershell
python .\experiments\plot_results.py --results results.json --out-dir plots
```

Notes
- The Kyber KEM uses the `pqcrypto` package (Kyber512/768/1024). If `pqcrypto` is not available, install it or adjust the code to your Kyber implementation.
- The RSA experiment uses PyCryptodome and generates rotated RSA keys per-iteration to simulate frequent rotations (configurable in `experiments/rsa_byok.py`). The Kyber experiment generates a single PQC keypair and reuses it, showing how PQC can allow long-lived BYOK keys.

Experiment semantics (important — how to read the graphs)

- Iterations: the `--iterations` parameter runs that many independent iterations and results are averaged / plotted across iterations.
- Symmetric keys: by default the demo generates a fresh symmetric AES key on each iteration (so `iterations=30` means 30 different symmetric keys were used).
- Kyber: a single PQC (Kyber-like) keypair is generated once and reused across all iterations to encapsulate each per-iteration symmetric key.
- RSA: by default the demo generates a new RSA keypair each iteration and uses it to encrypt the freshly generated symmetric key (simulates frequent RSA rotations).

When interpreting the plots: Kyber's key generation cost appears once (one-time), while RSA's key generation and protect costs are measured repeatedly (per-iteration) in the rotating-keys scenario. The plots and the generated `experiment_summary.png` include a short note summarizing these semantics.

Aggregate totals and formulas

- Aggregate totals (used in plots):
	- Kyber_total = ky['keygen_time'] + sum(ky['enc_times']) + sum(ky['sym_enc_times'])
	- RSA_total = sum(rsa['keygen_times']) + sum(rsa['enc_times']) + sum(rsa['sym_enc_times'])

- Key storage (used in plots):
	- Kyber_key_storage = ky['pk_size'] + ky['sk_size']
	- RSA_key_storage = sum(rs['pk_sizes']) + sum(rs['sk_sizes'])  (rotating keys)

Abbreviations and terms

- PQC: Post-Quantum Cryptography
- KEM: Key Encapsulation Mechanism — a public-key primitive that "encapsulates" a shared secret and returns a ciphertext and shared secret; the receiver "decapsulates" to recover the shared secret.
- DEM: Data Encapsulation Mechanism — symmetric encryption (here AES-GCM) used to encrypt application data.
- BYOK: Bring Your Own Key — the model where the data owner provides symmetric keys to encrypt data (we protect those keys with public-key ops).
- Encapsulate/Decapsulate: verbs used for KEMs (Kyber) rather than encrypt/decrypt because KEMs produce shared secrets rather than directly encrypting key bytes.
- RSA-OAEP: RSA encryption scheme used to wrap (encrypt) symmetric keys in this demo.

Reading the plots

- Per-iteration end-to-end plots show an amortized Kyber keygen contribution (one-time keygen divided by N) versus RSA per-iteration keygen when RSA is rotated on each iteration. Bars are stacked to show contribution breakdown: keygen (amortized), key-protection (KEM encaps or RSA encrypt), and symmetric encryption (AES-GCM).
- Aggregate totals show the absolute cost across N iterations to demonstrate how repeated RSA rotations increase total time and how Kyber's one-time cost amortizes over many operations.
- Key storage plot shows total bytes required to store keys across N iterations; Kyber requires only one keypair (one-time) while RSA rotating requires storing many keypairs, highlighting a storage benefit for Kyber in rotating scenarios.

If you want the demo to reflect different assumptions (e.g., reuse RSA keys, or derive symmetric keys from KEM shared secrets via HKDF), the scripts can be adjusted — tell me which variant you want and I will run and re-plot.
