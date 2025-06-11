# utils.py
import hashlib
from cryptography.fernet import Fernet

def hash_data(data):
    """Generate SHA-256 hash of data."""
    return hashlib.sha256(data.encode()).hexdigest()

def generate_key():
    """Generate and save AES-256 key."""
    key = Fernet.generate_key()
    with open("encryption_key.enc", "wb") as f:
        f.write(key)
    return key

def load_key():
    """Load AES-256 key."""
    try:
        with open("encryption_key.enc", "rb") as f:
            return f.read()
    except FileNotFoundError:
        return generate_key()

def encrypt_data(data, key):
    """Encrypt data with AES-256."""
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data, key):
    """Decrypt data with AES-256."""
    f = Fernet(key)
    return f.decrypt(encrypted_data.encode()).decode()
