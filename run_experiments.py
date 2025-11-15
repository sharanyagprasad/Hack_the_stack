import json
import argparse
from experiments.kyber_byok import run_kyber_byok
from experiments.rsa_byok import run_rsa_byok

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-file', default='data.txt')
    parser.add_argument('--iterations', type=int, default=20)
    parser.add_argument('--kyber-variant', default='kyber768')
    parser.add_argument('--rsa-key-size', type=int, default=2048)
    parser.add_argument('--out', default='results.json')
    args = parser.parse_args()

    with open(args.data_file, 'rb') as f:
        data = f.read()

    print('Running Kyber experiment...')
    kyber_res = run_kyber_byok(data, iterations=args.iterations, variant=args.kyber_variant)
    print('Running RSA experiment (rotating keys each iteration)...')
    rsa_res = run_rsa_byok(data, iterations=args.iterations, key_size=args.rsa_key_size, rotate_keys=True)

    # Add top-level metadata explaining the experiment semantics so plotting
    # and downstream analysis are unambiguous.
    results = {
        'meta': {
            'iterations': args.iterations,
            'sym_key_per_iteration': True,
            'kyber_reuses_pqc_key': True,
            'rsa_rotates_key_each_iteration': True,
            'description': (
                'Each iteration generates a fresh symmetric AES key. ' 
                'Kyber (PQC) keypair is generated once and reused across iterations. '
                'RSA keypair is generated per-iteration (simulates frequent rotation).'
            ),
        },
        'kyber': kyber_res,
        'rsa': rsa_res,
    }
    with open(args.out, 'w') as f:
        json.dump(results, f, indent=2)
    print('Saved combined results to', args.out)

if __name__ == '__main__':
    main()
