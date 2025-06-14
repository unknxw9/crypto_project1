from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

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