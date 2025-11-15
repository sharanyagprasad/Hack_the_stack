from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

def generate_sym_key(length=32):
    """Generate a symmetric key of `length` bytes (default 32 bytes = 256 bits)."""
    return secrets.token_bytes(length)

def aes_encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """Encrypt plaintext with AES-GCM. Returns nonce || ciphertext || tag as a single bytes blob."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ct

def aes_decrypt(key: bytes, blob: bytes, associated_data: bytes | None = None) -> bytes:
    """Decrypt a blob produced by `aes_encrypt` and return plaintext."""
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data)
