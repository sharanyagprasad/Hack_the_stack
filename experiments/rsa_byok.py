import time
from typing import Dict, Any, List
from experiments.symmetric_utils import generate_sym_key, aes_encrypt, aes_decrypt

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def run_rsa_byok(data: bytes, iterations: int = 20, key_size: int = 2048, rotate_keys: bool = True) -> Dict[str, Any]:
    # If rotate_keys is True, generate an RSA key per iteration (simulates frequent rotation)
    keygen_times: List[float] = []
    enc_times: List[float] = []
    dec_times: List[float] = []
    sym_enc_times: List[float] = []
    pk_sizes: List[int] = []
    sk_sizes: List[int] = []
    ct_sizes: List[int] = []

    for i in range(iterations):
        t0 = time.perf_counter()
        key = RSA.generate(key_size)
        t1 = time.perf_counter()
        keygen_times.append(t1 - t0)

        pk = key.publickey().export_key(format='DER')
        sk = key.export_key(format='DER')
        pk_sizes.append(len(pk))
        sk_sizes.append(len(sk))

        # generate a fresh symmetric key per iteration
        sym_key = generate_sym_key(32)

        # encrypt the symmetric key with RSA-OAEP
        cipher_rsa = PKCS1_OAEP.new(key.publickey())
        t0 = time.perf_counter()
        encrypted_sym = cipher_rsa.encrypt(sym_key)
        t1 = time.perf_counter()
        enc_times.append(t1 - t0)

        # decrypt with RSA-OAEP
        cipher_rsa_priv = PKCS1_OAEP.new(key)
        t0 = time.perf_counter()
        decrypted_sym = cipher_rsa_priv.decrypt(encrypted_sym)
        t1 = time.perf_counter()
        dec_times.append(t1 - t0)

        if decrypted_sym != sym_key:
            raise RuntimeError('RSA decrypted symmetric key mismatch')

        # Encrypt data with symmetric key
        t0 = time.perf_counter()
        cipher_blob = aes_encrypt(sym_key, data)
        t1 = time.perf_counter()
        sym_enc_times.append(t1 - t0)
        ct_sizes.append(len(cipher_blob))

    result = {
        'scheme': 'rsa',
        'key_size': key_size,
        'rotate_keys': rotate_keys,
        'avg_keygen_time': sum(keygen_times) / len(keygen_times),
        'keygen_times': keygen_times,
        'pk_sizes': pk_sizes,
        'sk_sizes': sk_sizes,
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
    parser.add_argument('--key-size', type=int, default=2048)
    parser.add_argument('--out', default='rsa_results.json')
    args = parser.parse_args()

    with open(args.data_file, 'rb') as f:
        data = f.read()

    res = run_rsa_byok(data, iterations=args.iterations, key_size=args.key_size, rotate_keys=True)
    with open(args.out, 'w') as f:
        json.dump(res, f, indent=2)
    print('Wrote', args.out)
