#!/usr/bin/env python3
"""
VERSIÓN 1.1 - AES + SHA256
Cliente con cifrado simétrico AES-256-GCM.
"""

import socket
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

HOST = 'localhost'
PORT = 9999

DEBUG = True

# Cargar clave simétrica
with open("keys/symmetric.key", "rb") as f:
    AES_KEY = base64.urlsafe_b64decode(f.read())

aesgcm = AESGCM(AES_KEY)

class AESEncryption:
    @staticmethod
    def encrypt(message: str):
        """Cifra mensaje usando AES-256-GCM."""
        start = time.perf_counter()
        
        try:
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
            encrypted_data = nonce + ciphertext
            
            end = time.perf_counter()
            if DEBUG:
                print(f"[DEBUG] Cifrado AES-SHA256 en {end - start:.6f} segundos")
            
            return encrypted_data
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] Error en cifrado: {e}")
            return None

    @staticmethod
    def decrypt(encrypted_data: bytes):
        """Descifra mensaje usando AES-256-GCM."""
        start = time.perf_counter()
        
        try:
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            end = time.perf_counter()
            if DEBUG:
                print(f"[DEBUG] Descifrado AES-SHA256 en {end - start:.6f} segundos")
            
            return plaintext.decode('utf-8')
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] Error en descifrado: {e}")
            return None

def receive_messages(sock):
    """Escucha mensajes cifrados del servidor."""
    while True:
        try:
            encrypted_data = sock.recv(4096)
            if not encrypted_data:
                print("\n[Sistema] Conexión cerrada por el servidor.")
                break
            
            message = AESEncryption.decrypt(encrypted_data)
            if message:
                print(f"\n{message}")
            else:
                print("\n[Sistema] Error descifrando mensaje.")
                
        except Exception as e:
            print(f"\n[Sistema] Error: {e}")
            break

def send_messages(sock):
    """Envía mensajes cifrados al servidor."""
    while True:
        msg = input()
        if not msg:
            continue

        encrypted = AESEncryption.encrypt(msg)
        if encrypted:
            sock.sendall(encrypted)

        if msg.lower() == 'exit':
            break
        print(f"[Tú] {msg}")

def run_client():
    print("=== CLIENTE - VERSIÓN 1.1 (AES + SHA256) ===")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    username = input("Nombre de usuario: ").strip()
    while not username:
        username = input("Nombre vacío. Introduce tu nombre: ").strip()
    
    # Enviar nombre de usuario cifrado
    encrypted_username = AESEncryption.encrypt(username)
    if encrypted_username:
        sock.sendall(encrypted_username)
        print("Conectado al chat seguro")
        print("Comunicación cifrada con AES-256-GCM + SHA256")
        print("Escribe mensajes (exit para salir):")
    else:
        print("Error cifrando nombre de usuario.")
        sock.close()
        return

    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()

    send_messages(sock)

    sock.close()
    print("Desconectado.")

if __name__ == '__main__':
    run_client()