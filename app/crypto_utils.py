# === app/crypto_utils.py ===
import hashlib
import base64
from cryptography.fernet import Fernet

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def generate_fernet_key(password):
    hash_digest = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash_digest)

def encrypt_data(data, password):
    key = generate_fernet_key(password)
    fernet = Fernet(key)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(token, password):
    key = generate_fernet_key(password)
    fernet = Fernet(key)
    return fernet.decrypt(token.encode()).decode()
