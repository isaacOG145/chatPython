#!/usr/bin/env python3
"""
VERSIÓN 1.0 - RSA + SHA256
Genera par de llaves RSA 2048 bits para el servidor.
Algoritmo: RSA + SHA256
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
import os

def generate_rsa_keys():
    print("Generando llaves RSA 2048 bits con SHA256...")
    
    # Generar clave privada RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Serializar clave privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serializar clave pública
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar archivos
    with open("keys/server_private.pem", "wb") as f:
        f.write(private_pem)

    with open("keys/server_public.pem", "wb") as f:
        f.write(public_pem)

    print("✓ Llaves RSA generadas: server_private.pem y server_public.pem")

def main():
    os.makedirs("keys", exist_ok=True)
    generate_rsa_keys()
    print("\nVERSIÓN 1.0 - Llaves RSA+SHA256 generadas correctamente")

if __name__ == "__main__":
    main()