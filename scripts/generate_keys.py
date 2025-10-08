# Código para generar clave para cifrado simétrico
from cryptography.fernet import Fernet
import os

def generate_key():
    """Genera una clave simétrica y la guarda en keys/symmetric.key"""
    key = Fernet.generate_key()
    with open("keys/symmetric.key", "wb") as f:
        f.write(key)
    print("Clave simétrica generada en 'keys/symmetric.key'.")

def main():
    os.makedirs("keys", exist_ok=True)
    print("Generando llave compartida...")
    generate_key()

if __name__ == "__main__":
    main()
