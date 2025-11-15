import json
import os
import math
import statistics
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def mean(lst):
    return float(statistics.mean(lst)) if lst else 0.0

def human_time(t: float) -> str:
    return f"{t:.6f}s"

def human_bytes(b: int) -> str:
    if b is None:
        return 'n/a'
    for unit in ['B','KB','MB','GB']:
        if b < 1024.0:
            return f"{b:.0f} {unit}"
        b /= 1024.0
    return f"{b:.0f} TB"

def plot_summary(results_file: str, out_dir: str = 'plots'):
    ensure_dir(out_dir)
    with open(results_file, 'r') as f:
        results = json.load(f)

    meta = results.get('meta', {})
    ky = results['kyber']
    rs = results['rsa']
    N = meta.get('iterations', ky.get('iterations', rs.get('iterations', None)))

    # short note
    note_lines = []
    if meta.get('sym_key_per_iteration'):
        note_lines.append('New symmetric key each iteration')
    if meta.get('kyber_reuses_pqc_key'):
        note_lines.append('Kyber: single PQC key reused')
    if meta.get('rsa_rotates_key_each_iteration'):
        note_lines.append('RSA: key rotated each iteration')
    note_text = ' | '.join(note_lines)

    # Compute stats
    ky_keygen_time = ky.get('keygen_time', 0.0)
    ky_enc_avg = mean(ky.get('enc_times', []))
    ky_dec_avg = mean(ky.get('dec_times', []))
    ky_sym_enc_avg = mean(ky.get('sym_enc_times', []))
    ky_enc_sum = sum(ky.get('enc_times', []))
    ky_sym_enc_sum = sum(ky.get('sym_enc_times', []))

    rsa_keygen_times = rs.get('keygen_times', [])
    rsa_keygen_avg = mean(rsa_keygen_times)
    rsa_enc_avg = mean(rs.get('enc_times', []))
    rsa_dec_avg = mean(rs.get('dec_times', []))
    rsa_sym_enc_avg = mean(rs.get('sym_enc_times', []))
    rsa_enc_sum = sum(rs.get('enc_times', []))
    rsa_sym_enc_sum = sum(rs.get('sym_enc_times', []))

    # Per-iteration end-to-end including amortized Kyber keygen
    ky_keygen_amortized = ky_keygen_time / N if N else 0.0
    ky_end2end_enc_per_iter = ky_keygen_amortized + ky_enc_avg + ky_sym_enc_avg
    rsa_end2end_enc_per_iter = rsa_keygen_avg + rsa_enc_avg + rsa_sym_enc_avg

    ky_end2end_dec_per_iter = ky_keygen_amortized + ky_dec_avg + ky_sym_enc_avg
    rsa_end2end_dec_per_iter = rsa_keygen_avg + rsa_dec_avg + ky_sym_enc_avg

    # Aggregate totals across N iterations
    ky_total = ky_keygen_time + ky_enc_sum + ky_sym_enc_sum
    rsa_total = sum(rsa_keygen_times) + rsa_enc_sum + rsa_sym_enc_sum

    # Key storage
    ky_key_storage = ky.get('pk_size', 0) + ky.get('sk_size', 0)
    rsa_key_storage = sum(rs.get('pk_sizes', [])) + sum(rs.get('sk_sizes', []))

    # Data ciphertext sizes
    ky_data_ct_avg = mean(ky.get('ct_sizes', []))
    rsa_data_ct_avg = mean(rs.get('ct_sizes', []))

    # Key-protection ciphertext size estimates
    ky_kem_ct_size = None
    try:
        variant = ky.get('variant', '')
        if variant.startswith('kyber'):
            from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
            mapping = {'kyber512': ml_kem_512, 'kyber768': ml_kem_768, 'kyber1024': ml_kem_1024}
            mod = mapping.get(variant)
            if mod:
                ky_kem_ct_size = getattr(mod, 'CIPHERTEXT_SIZE', None)
    except Exception:
        ky_kem_ct_size = None

    rsa_wrapped_size = None
    try:
        rsa_bits = rs.get('key_size', None)
        if rsa_bits:
            rsa_wrapped_size = math.ceil(rsa_bits / 8)
    except Exception:
        rsa_wrapped_size = None

    # ---- PLOT A: Per-iteration end-to-end encryption (amortized keygen) ----
    fig, ax = plt.subplots(figsize=(7,4))
    schemes = ['Kyber (amortized)', 'RSA (per-iter)']
    # Stacked components: keygen_amortized, key_protect, sym_enc
    ky_components = [ky_keygen_amortized, ky_enc_avg, ky_sym_enc_avg]
    rs_components = [rsa_keygen_avg, rsa_enc_avg, rsa_sym_enc_avg]
    bottoms = np.zeros(2)
    labels = ['keygen_amortized','key_protect','sym_encrypt']
    colors = ['#88C0D0','#81A1C1','#A3BE8C']
    for i, lab in enumerate(labels):
        vals = [ky_components[i], rs_components[i]]
        ax.bar(schemes, vals, bottom=bottoms, label=lab, color=colors[i])
        bottoms += np.array(vals)
    ax.set_ylabel('Time (s)')
    ax.set_xlabel('Scheme')
    ax.set_title(f'Per-iteration End-to-End Encryption Time (amortized Kyber keygen), N={N}')
    ax.set_yscale('linear')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    # numeric annotations
    for i, total in enumerate(bottoms):
        ax.text(i, total + max(bottoms)*0.005 if max(bottoms)>0 else 0, f'{total:.6f}s', ha='center')
    ax.legend()
    ax.text(0.01, 0.01, note_text, transform=fig.transFigure, fontsize=8, color='gray')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir,'end2end_encrypt_per_iter.png'))

    # ---- PLOT B: Per-iteration End-to-End Decryption (amortized) ----
    fig, ax = plt.subplots(figsize=(7,4))
    ky_components = [ky_keygen_amortized, ky_dec_avg, ky_sym_enc_avg]
    rs_components = [rsa_keygen_avg, rsa_dec_avg, ky_sym_enc_avg]
    bottoms = np.zeros(2)
    for i, lab in enumerate(labels):
        vals = [ky_components[i], rs_components[i]]
        ax.bar(schemes, vals, bottom=bottoms, label=lab, color=colors[i])
        bottoms += np.array(vals)
    ax.set_ylabel('Time (s)')
    ax.set_xlabel('Scheme')
    ax.set_title(f'Per-iteration End-to-End Decryption Time (amortized Kyber keygen), N={N}')
    ax.set_yscale('linear')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    for i, total in enumerate(bottoms):
        ax.text(i, total + max(bottoms)*0.005 if max(bottoms)>0 else 0, f'{total:.6f}s', ha='center')
    ax.legend()
    ax.text(0.01, 0.01, note_text, transform=fig.transFigure, fontsize=8, color='gray')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir,'end2end_decrypt_per_iter.png'))

    # ---- PLOT C: Aggregate total time across N iterations ----
    fig, ax = plt.subplots(figsize=(7,4))
    ky_total_components = [ky_keygen_time, ky_enc_sum, ky_sym_enc_sum]
    rsa_total_components = [sum(rsa_keygen_times), rsa_enc_sum, rsa_sym_enc_sum]
    bottoms = np.zeros(2)
    for i, lab in enumerate(labels):
        vals = [ky_total_components[i], rsa_total_components[i]]
        ax.bar(['Kyber_total','RSA_total'], vals, bottom=bottoms, label=lab, color=colors[i])
        bottoms += np.array(vals)
    ax.set_ylabel('Time (s)')
    ax.set_xlabel('Scheme')
    ax.set_title(f'Aggregate Total Time for N={N} iterations')
    ax.set_yscale('linear')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    for i, total in enumerate(bottoms):
        ax.text(i, total + max(bottoms)*0.005 if max(bottoms)>0 else 0, f'{total:.6f}s', ha='center')
    ax.legend()
    ax.text(0.01, 0.01, note_text, transform=fig.transFigure, fontsize=8, color='gray')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir,'aggregate_total_time.png'))

    # ---- PLOT D: Key storage for N iterations ----
    fig, ax = plt.subplots(figsize=(6,3))
    schemes = ['Kyber (one-time)','RSA (rotating)']
    storage_vals = [ky_key_storage, rsa_key_storage]
    ax.bar(schemes, storage_vals, color=['C0','C1'])
    ax.set_ylabel('Total key storage (bytes)')
    ax.set_xlabel('Scheme')
    ax.set_title(f'Total Key Storage for N={N} iterations')
    ax.set_yscale('linear')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    for i, v in enumerate(storage_vals):
        ax.text(i, v + max(storage_vals)*0.01 if max(storage_vals)>0 else 0, human_bytes(int(v)), ha='center')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir,'key_storage_total.png'))

    # ---- PLOT E: Key-protection ciphertext sizes (estimated) ----
    fig, ax = plt.subplots(figsize=(6,3))
    ky_kem_ct = ky_kem_ct_size if ky_kem_ct_size else 0
    rs_wrapped_ct = rsa_wrapped_size if rsa_wrapped_size else 0
    ax.bar(['Kyber KEM ct','RSA wrapped key'], [ky_kem_ct, rs_wrapped_ct], color=['C2','C3'])
    ax.set_ylabel('Size (bytes)')
    ax.set_xlabel('Key-protection scheme')
    ax.set_title('Key-Protection Ciphertext Size (per-iteration, estimated)')
    ax.set_yscale('linear')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    ax.text(0, ky_kem_ct + max(ky_kem_ct, rs_wrapped_ct)*0.01 if max(ky_kem_ct, rs_wrapped_ct)>0 else 0, f'{ky_kem_ct if ky_kem_ct else "n/a"} bytes')
    ax.text(1, rs_wrapped_ct + max(ky_kem_ct, rs_wrapped_ct)*0.01 if max(ky_kem_ct, rs_wrapped_ct)>0 else 0, f'{rs_wrapped_ct if rs_wrapped_ct else "n/a"} bytes')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir,'key_protection_ct_sizes.png'))

    # ---- PLOT F: Data ciphertext sizes (AES-GCM) ----
    fig, ax = plt.subplots(figsize=(6,3))
    ax.bar(['Kyber BYOK','RSA BYOK'], [ky_data_ct_avg, rsa_data_ct_avg], color=['C4','C5'])
    ax.set_ylabel('Size (bytes)')
    ax.set_xlabel('Scheme')
    ax.set_title('Data Ciphertext Size (AES-GCM) (per-iteration)')
    ax.set_yscale('linear')
    ax.grid(axis='y', linestyle='--', alpha=0.4)
    for i, v in enumerate([ky_data_ct_avg, rsa_data_ct_avg]):
        ax.text(i, v + max(ky_data_ct_avg, rsa_data_ct_avg)*0.01 if max(ky_data_ct_avg, rsa_data_ct_avg)>0 else 0, f'{int(v)} bytes')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir,'data_ciphertext_size.png'))

    # ---- PLOT G: Per-iteration traces for encapsulation/encryption and decapsulation/decryption ----
    fig, axs = plt.subplots(2,1, figsize=(8,6), sharex=True)
    axs[0].plot(ky.get('enc_times', []), label='Kyber encaps')
    axs[0].plot(rs.get('enc_times', []), label='RSA encrypt key')
    axs[0].set_ylabel('Time (s)')
    axs[0].legend()
    axs[0].set_title('Per-iteration key-protection times (encapsulate/encrypt)')

    axs[1].plot(ky.get('dec_times', []), label='Kyber decaps')
    axs[1].plot(rs.get('dec_times', []), label='RSA decrypt key')
    axs[1].set_ylabel('Time (s)')
    axs[1].set_xlabel('Iteration')
    axs[1].legend()
    fig.tight_layout()
    if note_text:
        fig.text(0.5, 0.01, note_text, ha='center', va='bottom', fontsize=9, color='gray')
    fig.savefig(os.path.join(out_dir,'per_iteration_traces.png'))

    print('Saved annotated plots to', out_dir)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--results', default='../results.json')
    parser.add_argument('--out-dir', default='plots')
    args = parser.parse_args()
    plot_summary(args.results, args.out_dir)
import json
import os
import math
import statistics
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)

def plot_summary(results_file: str, out_dir: str = 'plots'):
    ensure_dir(out_dir)
    with open(results_file, 'r') as f:
        results = json.load(f)

    meta = results.get('meta', {})
    ky = results['kyber']
    rs = results['rsa']
    iterations = meta.get('iterations', ky.get('iterations', rs.get('iterations', None)))
    # Short descriptive note to annotate plots
    note_lines = []
    if meta:
        if meta.get('sym_key_per_iteration'):
            note_lines.append('New symmetric key each iteration')
        if meta.get('kyber_reuses_pqc_key'):
            note_lines.append('Kyber: single PQC key reused')
        if meta.get('rsa_rotates_key_each_iteration'):
            note_lines.append('RSA: key rotated each iteration')
    note_text = ' | '.join(note_lines)

    # Compute core statistics
    N = iterations
    def mean(lst):
        return float(statistics.mean(lst)) if lst else 0.0

    ky_keygen_time = ky.get('keygen_time', 0.0)
    ky_enc_avg = mean(ky.get('enc_times', []))
    ky_dec_avg = mean(ky.get('dec_times', []))
    ky_sym_enc_avg = mean(ky.get('sym_enc_times', []))
    ky_sym_enc_sum = sum(ky.get('sym_enc_times', []))
    ky_enc_sum = sum(ky.get('enc_times', []))

    rsa_keygen_times = rs.get('keygen_times', [])
    rsa_keygen_avg = mean(rsa_keygen_times)
    rsa_enc_avg = mean(rs.get('enc_times', []))
    rsa_dec_avg = mean(rs.get('dec_times', []))
    rsa_sym_enc_avg = mean(rs.get('sym_enc_times', []))
    rsa_enc_sum = sum(rs.get('enc_times', []))
    rsa_sym_enc_sum = sum(rs.get('sym_enc_times', []))

    # Symmetric decrypt time is not measured; assume symmetric decrypt ~= encrypt
    sym_dec_avg = ky_sym_enc_avg

    # Per-iteration end-to-end (amortized Kyber keygen)
    ky_keygen_amortized = ky_keygen_time / N if N else 0.0
    ky_end2end_enc_per_iter = ky_keygen_amortized + ky_enc_avg + ky_sym_enc_avg
    rsa_end2end_enc_per_iter = rsa_keygen_avg + rsa_enc_avg + rsa_sym_enc_avg

    ky_end2end_dec_per_iter = ky_keygen_amortized + ky_dec_avg + sym_dec_avg
    rsa_end2end_dec_per_iter = rsa_keygen_avg + rsa_dec_avg + sym_dec_avg

    # Aggregate totals across N iterations
    ky_total = ky_keygen_time + ky_enc_sum + ky_sym_enc_sum + (N * 0)  # sym key gen time ignored
    rsa_total = sum(rsa_keygen_times) + rsa_enc_sum + rsa_sym_enc_sum + (N * 0)

    # Key storage for N iterations
    ky_key_storage = ky.get('pk_size', 0) + ky.get('sk_size', 0)
    rsa_pk_sizes = rs.get('pk_sizes', [])
    rsa_sk_sizes = rs.get('sk_sizes', [])
    rsa_key_storage = sum(rsa_pk_sizes) + sum(rsa_sk_sizes)

    # Key-protection ciphertext sizes (per iteration): try to compute/estimate
    ky_kem_ct_size = None
    try:
        # import appropriate pqcrypto module to read CIPHERTEXT_SIZE
        variant = ky.get('variant', '')
        if variant.startswith('kyber'):
            from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
            mapping = {'kyber512': ml_kem_512, 'kyber768': ml_kem_768, 'kyber1024': ml_kem_1024}
            mod = mapping.get(variant)
            if mod:
                ky_kem_ct_size = getattr(mod, 'CIPHERTEXT_SIZE', None)
    except Exception:
        ky_kem_ct_size = None

    rsa_wrapped_size = None
    try:
        rsa_bits = rs.get('key_size', None)
        if rsa_bits:
            rsa_wrapped_size = math.ceil(rsa_bits / 8)
    except Exception:
        rsa_wrapped_size = None

    # Data ciphertext sizes (AES-GCM) average
    ky_data_ct_avg = mean(ky.get('ct_sizes', []))
    rsa_data_ct_avg = mean(rs.get('ct_sizes', []))


    # Key sizes
    labels = ['public_key', 'private_key']
    ky_sizes = [ky['pk_size'], ky['sk_size']]
    rs_sizes = [int(np.mean(rs['pk_sizes'])), int(np.mean(rs['sk_sizes']))]

    x = np.arange(len(labels))
    width = 0.35
    fig, ax = plt.subplots()
    ax.bar(x - width/2, ky_sizes, width, label='Kyber (' + ky['variant'] + ')')
    ax.bar(x + width/2, rs_sizes, width, label=f'RSA ({rs["key_size"]} bit, rotated)')
    ax.set_ylabel('Size (bytes)')
    ax.set_title(f'Average Key Sizes (iterations={iterations})')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, 'key_sizes.png'))

    # Timing comparisons: mean values
    ky_enc = np.mean(ky['enc_times'])
    ky_dec = np.mean(ky['dec_times'])
    rs_enc = np.mean(rs['enc_times'])
    rs_dec = np.mean(rs['dec_times'])

    labels = ['encapsulate(encrypt key)', 'decapsulate(decrypt key)']
    ky_vals = [ky_enc, ky_dec]
    rs_vals = [rs_enc, rs_dec]
    x = np.arange(len(labels))

    fig, ax = plt.subplots()
    ax.bar(x - width/2, ky_vals, width, label='Kyber')
    ax.bar(x + width/2, rs_vals, width, label='RSA (rotating)')
    ax.set_ylabel('Time (s)')
    ax.set_title(f'Average KEM / RSA key protect times (iterations={iterations})')
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, 'kem_vs_rsa_times.png'))

    # Symmetric encryption times
    ky_sym = np.mean(ky['sym_enc_times'])
    rs_sym = np.mean(rs['sym_enc_times'])
    fig, ax = plt.subplots()
    ax.bar(['Kyber BYOK', 'RSA BYOK'], [ky_sym, rs_sym], color=['C0', 'C1'])
    ax.set_ylabel('Time (s)')
    ax.set_title(f'Average Symmetric Encryption Time (AES-GCM) (iterations={iterations})')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, 'sym_enc_times.png'))

    # Ciphertext sizes
    ky_ct = np.mean(ky['ct_sizes'])
    rs_ct = np.mean(rs['ct_sizes'])
    fig, ax = plt.subplots()
    ax.bar(['Kyber BYOK', 'RSA BYOK'], [ky_ct, rs_ct], color=['C2', 'C3'])
    ax.set_ylabel('Size (bytes)')
    ax.set_title(f'Average Ciphertext Size (encrypted data) (iterations={iterations})')
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, 'ciphertext_sizes.png'))

    # Iteration traces for encapsulation/decapsulation
    fig, axs = plt.subplots(2, 1, figsize=(8, 6), sharex=True)
    axs[0].plot(ky['enc_times'], label='Kyber encaps')
    axs[0].plot(rs['enc_times'], label='RSA encrypt key')
    axs[0].set_ylabel('Time (s)')
    axs[0].legend()
    axs[0].set_title('Per-iteration encapsulation/encryption times')

    axs[1].plot(ky['dec_times'], label='Kyber decaps')
    axs[1].plot(rs['dec_times'], label='RSA decrypt key')
    axs[1].set_ylabel('Time (s)')
    axs[1].set_xlabel('Iteration')
    axs[1].legend()
    fig.tight_layout()
    # Add the explanatory note as a footer on the per-iteration figure
    if note_text:
        fig.text(0.5, 0.01, note_text, ha='center', va='bottom', fontsize=9, color='gray')
    fig.savefig(os.path.join(out_dir, 'per_iteration_kem_rsa.png'))

    # Also create a small summary image explaining experiment semantics
    fig2, ax2 = plt.subplots(figsize=(8, 2))
    ax2.axis('off')
    summary = f"Iterations: {iterations}    {note_text}"
    ax2.text(0.01, 0.6, 'Experiment Summary:', fontsize=10, weight='bold')
    ax2.text(0.01, 0.2, summary, fontsize=9)
    fig2.tight_layout()
    fig2.savefig(os.path.join(out_dir, 'experiment_summary.png'))

    print('Saved plots to', out_dir)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--results', default='../results.json')
    parser.add_argument('--out-dir', default='plots')
    args = parser.parse_args()
    plot_summary(args.results, args.out_dir)
