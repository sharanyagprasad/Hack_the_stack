import time
from typing import Dict, Any, List, Tuple
from experiments.symmetric_utils import generate_sym_key, aes_encrypt, aes_decrypt

def _select_kyber_module(variant: str):
    # pqcrypto distributions in this environment expose Kyber-like
    # implementations under ml_kem_512/768/1024. Map commonly used
    # kyber variant names to those modules.
    from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
    mapping = {
        'kyber512': ml_kem_512,
        'kyber768': ml_kem_768,
        'kyber1024': ml_kem_1024,
        'ml_kem_512': ml_kem_512,
        'ml_kem_768': ml_kem_768,
        'ml_kem_1024': ml_kem_1024,
    }
    if variant not in mapping:
        raise ValueError('Unsupported Kyber variant: ' + variant)
    return mapping[variant]

def run_kyber_byok(data: bytes, iterations: int = 20, variant: str = 'kyber768') -> Dict[str, Any]:
    mod = _select_kyber_module(variant)

    # Key generation (one-time for PQC BYOK)
    t0 = time.perf_counter()
    pk, sk = mod.generate_keypair()
    t1 = time.perf_counter()
    keygen_time = t1 - t0

    pk_size = len(pk)
    sk_size = len(sk)

    enc_times: List[float] = []
    dec_times: List[float] = []
    sym_enc_times: List[float] = []
    ct_sizes: List[int] = []

    for i in range(iterations):
        # generate a fresh symmetric key for each data encryption
        sym_key = generate_sym_key(32)

        # encapsulate symmetric key (public-key operation)
        t0 = time.perf_counter()
        ct, shared_enc_key = mod.encrypt(pk)
        t1 = time.perf_counter()
        enc_times.append(t1 - t0)

        # decapsulate (private-key operation)
        t0 = time.perf_counter()
        shared_dec_key = mod.decrypt(sk, ct)
        t1 = time.perf_counter()
        dec_times.append(t1 - t0)

        # Note: pqcrypto KEM produces a shared secret (shared_enc_key) which
        # in real KEM+DEM you'd derive a symmetric key via KDF. For demo purposes
        # we verify shared_enc_key equality and then use our generated sym_key
        # to encrypt the dataset (BYOK scenario: data key is protected by KEM).
        if shared_enc_key != shared_dec_key:
            raise RuntimeError('Kyber shared secrets do not match')

        # Encrypt the data with the per-iteration symmetric key and measure time
        t0 = time.perf_counter()
        cipher_blob = aes_encrypt(sym_key, data)
        t1 = time.perf_counter()
        sym_enc_times.append(t1 - t0)
        ct_sizes.append(len(cipher_blob))

    result = {
        'scheme': 'kyber',
        'variant': variant,
        'keygen_time': keygen_time,
        'pk_size': pk_size,
        'sk_size': sk_size,
        'enc_times': enc_times,
        'dec_times': dec_times,
        'sym_enc_times': sym_enc_times,
        'ct_sizes': ct_sizes,
        'iterations': iterations,
    }
    return result

if __name__ == '__main__':
    import argparse, json

    parser = argparse.ArgumentParser()
    parser.add_argument('--data-file', default='../data.txt')
    parser.add_argument('--iterations', type=int, default=20)
    parser.add_argument('--variant', default='kyber768')
    parser.add_argument('--out', default='kyber_results.json')
    args = parser.parse_args()

    with open(args.data_file, 'rb') as f:
        data = f.read()

    res = run_kyber_byok(data, iterations=args.iterations, variant=args.variant)
    with open(args.out, 'w') as f:
        json.dump(res, f, indent=2)
    print('Wrote', args.out)
