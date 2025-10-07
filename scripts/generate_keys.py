#!/usr/bin/env python3
"""
Script para generar claves RSA asimétricas del servidor.
Crea la carpeta /keys en el raíz del proyecto (si no existe)
y genera los archivos server_private.pem y server_public.pem.

Uso:
    python scripts/generate_keys.py [--force] [--bits 2048|4096] [--passphrase]
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

def generate_rsa_keys(prefix):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"keys/{prefix}_private.pem", "wb") as f:
        f.write(private_pem)

    with open(f"keys/{prefix}_public.pem", "wb") as f:
        f.write(public_pem)

    print(f"🔑 Llaves generadas: {prefix}_private.pem y {prefix}_public.pem")

def main():
    os.makedirs("keys", exist_ok=True)

    print("Generando llaves RSA para servidor y cliente...")
    generate_rsa_keys("server")
    generate_rsa_keys("client")
    print("\n✅ Todas las llaves se han generado correctamente en /keys")

if __name__ == "__main__":
    main()
