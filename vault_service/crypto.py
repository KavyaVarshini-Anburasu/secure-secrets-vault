import base64
import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))

def load_master_key() -> bytes:
    # 32 bytes for AES-256
    key_b64 = os.getenv("MASTER_KEY_B64")
    if not key_b64:
        raise RuntimeError("Missing MASTER_KEY_B64 in environment")
    key = _b64d(key_b64)
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY_B64 must decode to 32 bytes")
    return key

@dataclass
class EncryptedBlob:
    ciphertext_b64: str
    nonce_b64: str
    enc_dek_b64: str
    dek_nonce_b64: str

def encrypt_secret(plaintext: str) -> EncryptedBlob:
    master_key = load_master_key()

    # 1) Generate random DEK
    dek = os.urandom(32)
    dek_nonce = os.urandom(12)
    master_aes = AESGCM(master_key)
    enc_dek = master_aes.encrypt(dek_nonce, dek, None)

    # 2) Encrypt plaintext using DEK
    data_nonce = os.urandom(12)
    aes = AESGCM(dek)
    ciphertext = aes.encrypt(data_nonce, plaintext.encode("utf-8"), None)

    return EncryptedBlob(
        ciphertext_b64=_b64e(ciphertext),
        nonce_b64=_b64e(data_nonce),
        enc_dek_b64=_b64e(enc_dek),
        dek_nonce_b64=_b64e(dek_nonce),
    )

def decrypt_secret(blob: EncryptedBlob) -> str:
    master_key = load_master_key()

    master_aes = AESGCM(master_key)
    dek = master_aes.decrypt(_b64d(blob.dek_nonce_b64), _b64d(blob.enc_dek_b64), None)

    aes = AESGCM(dek)
    plaintext = aes.decrypt(_b64d(blob.nonce_b64), _b64d(blob.ciphertext_b64), None)
    return plaintext.decode("utf-8")
