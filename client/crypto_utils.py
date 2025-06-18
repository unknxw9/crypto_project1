# crypto_utils.py NEW
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES  # <-- 导入 AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes # <-- 导入 get_random_bytes
from typing import Optional

def load_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())

def encrypt_with_public_key(data: bytes, pubkey: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data)

def decrypt_with_private_key(ciphertext: bytes, privkey: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext)

def sign_with_private_key(data: bytes, privkey: RSA.RsaKey) -> bytes:
    h = SHA256.new(data)
    signature = pkcs1_15.new(privkey).sign(h)
    return signature

def verify_signature(data: bytes, signature: bytes, pubkey: RSA.RsaKey) -> bool:
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def encrypt_with_aes(data: bytes, session_key: bytes) -> tuple[bytes, bytes, bytes]:
    """使用AES-EAX模式加密数据"""
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, cipher.nonce, tag

def decrypt_with_aes(ciphertext: bytes, nonce: bytes, tag: bytes, session_key: bytes) -> Optional[bytes]:
    """使用AES-EAX模式解密数据"""
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data
    except (ValueError, KeyError):
        # 解密或验证失败
        return None