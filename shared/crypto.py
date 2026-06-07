"""
GhostWire Crypto Module.
========================
Handles all encryption and decryption for C2 traffic.

Two-layer encryption:
1. RSA-2048 - Used ONCE to exchange the AES key safely
2. AES-256-CTR - Used for ALL data after key exchange

Why both?
RSA alone = too slow for large data
AES alone = key distribution problem(how to share the key?)
RSA + AES = RSA protects the key exchange, AES protects the data.
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend


# ============================================================
# AES-256 ENCRYPTION
# ============================================================

class AESCipher:
    """AES-256-CTR mode encryption."""

    def __init__(self, key):
        if len(key) != 32:
            raise ValueError(f"AES key must be 32 bytes, got {len(key)}")
        self.key = key

    def encrypt(self, plaintext):
        """Encrypt plaintext with AES-256-CTR. Returns base64 string."""
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()

        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        encrypted = iv + ciphertext
        return base64.b64encode(encrypted).decode('ascii')

    def decrypt(self, encrypted_b64):
        """Decrypt base64-encoded AES-256-CTR data."""
        encrypted = base64.b64decode(encrypted_b64)
        iv = encrypted[:16]
        ciphertext = encrypted[16:]

        cipher = Cipher(
            algorithms.AES(self.key),
            modes.CTR(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')


# ============================================================
# RSA-2048 KEY MANAGEMENT
# ============================================================

class RSAKeyManager:
    """Manages RSA-2048 key pair generation, saving, and loading."""

    @staticmethod
    def generate_keys():
        """Generate a new RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_private_key(private_key, filepath):
        """Save RSA private key to PEM file."""
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(pem)

    @staticmethod
    def save_public_key(public_key, filepath):
        """Save RSA public key to PEM file."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(pem)

    @staticmethod
    def load_private_key(filepath):
        """Load RSA private key from PEM file."""
        with open(filepath, 'rb') as f:
            pem = f.read()
        return serialization.load_pem_private_key(
            pem,
            password=None,
            backend=default_backend()
        )

    @staticmethod
    def load_public_key(filepath):
        """Load RSA public key from PEM file."""
        with open(filepath, 'rb') as f:
            pem = f.read()
        return serialization.load_pem_public_key(
            pem,
            backend=default_backend()
        )

    @staticmethod
    def encrypt_key(aes_key, public_key):
        """Encrypt an AES key with RSA public key."""
        encrypted = public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('ascii')

    @staticmethod
    def decrypt_key(encrypted_b64, private_key):
        """Decrypt an AES key with RSA private key."""
        encrypted = base64.b64decode(encrypted_b64)
        aes_key = private_key.decrypt(
            encrypted,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return aes_key


# ============================================================
# SESSION KEY GENERATOR
# ============================================================

def generate_session_key():
    """Generate a random 32-byte AES-256 session key."""
    return os.urandom(32)


