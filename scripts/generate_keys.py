#!/usr/bin/env python3
"""
VERSIÓN 1.1 - AES + SHA256
Genera clave simétrica usando SHA256 para derivación.
Solo usa librería cryptography.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

def generate_symmetric_key():
    """Genera clave AES derivada con SHA256."""
    print("Generando clave simétrica AES con SHA256...")
    
    passphrase = "chat_secure_passphrase_v1_1"
    
    salt = b'chat_salt_v1_1_' 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000,
    )
    
    key = kdf.derive(passphrase.encode())
    
    with open("keys/symmetric.key", "wb") as f:
        f.write(base64.urlsafe_b64encode(key))
    
    print("Clave simétrica AES-SHA256 generada en 'keys/symmetric.key'")
    print(f"Algoritmo: AES-256-GCM")
    print(f"Derivación: PBKDF2-HMAC-SHA256")

def main():
    os.makedirs("keys", exist_ok=True)
    generate_symmetric_key()

if __name__ == "__main__":
    main()