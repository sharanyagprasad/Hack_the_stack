"""Measure RSA encryption time vs modulus size.

Two modes:
- pkcs1: generate RSA keys with typical small exponent (65537) and measure
  PKCS1_OAEP.encrypt() time (practical case).
- manual_pow: build modulus n=p*q and perform pow(m, e, n) with a large exponent
  of ~n bits to demonstrate the worst-case exponent-dependent scaling.

Usage examples:
  # practical PKCS1-OAEP measurements (fast)
  python complexity\rsa_complexity.py --mode pkcs1 --bits 512 1024 1536 2048 --trials 200

  # manual pow to show exponent scaling (faster than generating huge RSA keys)
  python complexity\rsa_complexity.py --mode manual_pow --bits 512 1024 1536 2048 --trials 500

The script writes `rsa_complexity_results.json` and `rsa_complexity_plot.png`.
"""

import argparse
import json
import time
import os
import math
import statistics
from typing import List

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util import number
import matplotlib.pyplot as plt
import numpy as np


def measure_pkcs1(bits_list: List[int], trials: int, out_dir: str):
    results = {}
    for bits in bits_list:
        print(f'Generating RSA key {bits}-bit (e=65537) ...')
        key = RSA.generate(bits)
        pub = key.publickey()
        cipher = PKCS1_OAEP.new(pub)
        # message: 32-byte symmetric key
        m = get_random_bytes(32)
        # warmup
        _ = cipher.encrypt(m)
        times = []
        for i in range(trials):
            t0 = time.perf_counter()
            _ = cipher.encrypt(m)
            t1 = time.perf_counter()
            times.append(t1 - t0)
        results[bits] = {
            'mode': 'pkcs1',
            'bits': bits,
            'trials': trials,
            'avg_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'times': times,
        }
        print(f'  avg encrypt time = {results[bits]["avg_time"]:.6f}s')
    path = os.path.join(out_dir, 'rsa_pkcs1_results.json')
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)
    return results


def measure_manual_pow(bits_list: List[int], trials: int, out_dir: str):
    results = {}
    for bits in bits_list:
        print(f'Generating primes for modulus ~{bits} bits...')
        p = number.getPrime(bits // 2)
        q = number.getPrime(bits - bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        # create a large exponent e roughly of size `bits` (worst-case scaling)
        # choose a random odd e of `bits` bits and ensure gcd(e, phi) == 1
        while True:
            e = number.getPrime(bits - 1)  # roughly bits-sized prime exponent
            if math.gcd(e, phi) == 1:
                break
        # pick message m
        m = number.getRandomRange(2, n - 1)
        # warmup pow
        _ = pow(m, e, n)
        times = []
        for i in range(trials):
            t0 = time.perf_counter()
            _ = pow(m, e, n)
            t1 = time.perf_counter()
            times.append(t1 - t0)
        results[bits] = {
            'mode': 'manual_pow',
            'bits': bits,
            'trials': trials,
            'avg_time': statistics.mean(times),
            'median_time': statistics.median(times),
            'times': times,
            'e_bits': e.bit_length(),
        }
        print(f'  avg pow time = {results[bits]["avg_time"]:.6f}s')
    path = os.path.join(out_dir, 'rsa_manualpow_results.json')
    with open(path, 'w') as f:
        json.dump(results, f, indent=2)
    return results


def plot_results(pkcs1_res, pow_res, out_dir: str):
    ensure_dir(out_dir)
    # Prepare data
    fig, ax = plt.subplots(figsize=(8,5))
    if pkcs1_res:
        bits = sorted(pkcs1_res.keys())
        pk_times = [pkcs1_res[b]['avg_time'] for b in bits]
        ax.plot(bits, pk_times, 'o-', label='PKCS1_OAEP (e=65537)')
    if pow_res:
        bits2 = sorted(pow_res.keys())
        pow_times = [pow_res[b]['avg_time'] for b in bits2]
        ax.plot(bits2, pow_times, 's-', label='manual pow (large e)')

    # reference curves: n^2 and n^3 (scaled)
    all_bits = sorted(set(list(pkcs1_res.keys()) if pkcs1_res else []) | set(list(pow_res.keys()) if pow_res else []))
    if all_bits:
        xs = np.array(all_bits)
        # fit scaling factors to make curves appear near the data
        if pkcs1_res:
            yref = np.array([pkcs1_res[x]['avg_time'] for x in xs if x in pkcs1_res])
        else:
            yref = np.array([pow_res[x]['avg_time'] for x in xs if x in pow_res])
        if yref.size > 0:
            # compute scale for n^2 to match first point
            n = xs.astype(float)
            scale2 = yref[0] / (n[0] ** 2)
            scale3 = yref[0] / (n[0] ** 3)
            ax.plot(xs, scale2 * (n ** 2), '--', color='gray', label=r'const * n^2')
            ax.plot(xs, scale3 * (n ** 3), '--', color='black', label=r'const * n^3')

    ax.set_xscale('linear')
    # ax.set_yscale('log')
    ax.set_xlabel('RSA modulus size (bits)')
    ax.set_ylabel('Average encryption time (s) [log scale]')
    ax.set_title('RSA encryption time vs modulus size')
    ax.grid(True, which='both', ls='--', alpha=0.4)
    ax.legend()
    fig.tight_layout()
    path = os.path.join(out_dir, 'rsa_complexity_plot.png')
    fig.savefig(path)
    print('Saved plot to', path)


def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['pkcs1', 'manual_pow', 'both'], default='both')
    parser.add_argument('--bits', type=int, nargs='+', default=[512, 1024, 1536, 2048])
    parser.add_argument('--trials', type=int, default=200)
    parser.add_argument('--out-dir', default='complexity_output')
    args = parser.parse_args()

    ensure_dir(args.out_dir)
    pkcs1_res = {}
    pow_res = {}
    if args.mode in ('pkcs1', 'both'):
        pkcs1_res = measure_pkcs1(args.bits, args.trials, args.out_dir)
    if args.mode in ('manual_pow', 'both'):
        pow_res = measure_manual_pow(args.bits, args.trials, args.out_dir)

    plot_results(pkcs1_res if pkcs1_res else None, pow_res if pow_res else None, args.out_dir)


if __name__ == '__main__':
    main()
