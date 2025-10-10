#!/usr/bin/env python3
"""
VERSIÓN 1.0 - RSA + SHA256
Cliente con cifrado asimétrico RSA y hashing SHA256.
Solo usa 2 llaves (servidor).
"""

import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'localhost'
PORT = 9999

DEBUG = True

def encrypt_message(public_key, message: str):
    """Cifra mensaje con RSA y padding OAEP-SHA256."""
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def decrypt_message(private_key, ciphertext: bytes):
    """Descifra mensaje con RSA y padding OAEP-SHA256."""
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
    return decrypted

def receive_messages(sock):
    """Hilo que recibe mensajes en texto plano del servidor."""
    while True:
        try:
            message = sock.recv(4096).decode('utf-8')
            if not message:
                print("\n[Sistema] Conexión cerrada por el servidor.")
                break
            print(f"\n{message}")
        except Exception as e:
            print(f"\n[Sistema] Error: {e}")
            break

def send_messages(sock, server_public_key):
    """Hilo que envía mensajes cifrados al servidor."""
    while True:
        msg = input()
        if not msg:
            continue

        # Cifrar mensaje con llave pública del servidor
        encrypted = encrypt_message(server_public_key, msg)
        sock.sendall(encrypted)

        if msg.lower() == 'exit':
            break
        print(f"[Tú] {msg}")

def run_client():
    print("=== CLIENTE - VERSIÓN 1.0 (RSA + SHA256) ===")
    
    # Conectar al servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Enviar nombre de usuario
    username = input("Nombre de usuario: ").strip()
    while not username:
        username = input("Nombre vacío. Introduce tu nombre: ").strip()
    sock.sendall(username.encode('utf-8'))

    # Recibir llave pública del servidor
    server_public_pem = sock.recv(4096)
    server_public_key = serialization.load_pem_public_key(server_public_pem)

    print("✅ Llave pública del servidor recibida")
    print("🔒 Comunicación cifrada con RSA + SHA256")
    print("💬 Escribe mensajes (exit para salir):")

    # Hilo para recibir mensajes (texto plano)
    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()
    
    # Enviar mensajes cifrados
    send_messages(sock, server_public_key)

    sock.close()
    print("🔌 Desconectado.")

if __name__ == '__main__':
    run_client()