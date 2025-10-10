#!/usr/bin/env python3
"""
VERSIÓN 1.1 - AES + SHA256
Servidor con cifrado simétrico AES-256-GCM.
"""

import socket
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os

HOST = 'localhost'
PORT = 9999

clients = {}
clients_lock = threading.Lock()

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
            # Generar nonce único (12 bytes para GCM)
            nonce = os.urandom(12)
            
            # Cifrar mensaje
            ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
            
            # Combinar nonce + ciphertext
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
            # Separar nonce (12) y ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Descifrar mensaje
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            end = time.perf_counter()
            if DEBUG:
                print(f"[DEBUG] Descifrado AES-SHA256 en {end - start:.6f} segundos")
            
            return plaintext.decode('utf-8')
        except Exception as e:
            if DEBUG:
                print(f"[DEBUG] Error en descifrado: {e}")
            return None

def broadcast(message: str, sender_sock=None):
    """Envía mensaje cifrado a todos los clientes excepto el remitente."""
    encrypted_msg = AESEncryption.encrypt(message)
    if not encrypted_msg:
        return
        
    with clients_lock:
        for client in list(clients.keys()):
            if client is sender_sock:
                continue
            try:
                client.sendall(encrypted_msg)
            except Exception as e:
                if DEBUG:
                    print(f"[DEBUG] Error enviando a cliente: {e}")
                remove_client(client)

def remove_client(client_sock):
    """Elimina y cierra el socket del cliente."""
    with clients_lock:
        clients.pop(client_sock, None)
    try:
        client_sock.close()
    except:
        pass

def handle_client(client_sock, addr):
    try:
        # Recibir nombre de usuario cifrado
        encrypted_username = client_sock.recv(1024)
        username = AESEncryption.decrypt(encrypted_username)
        if not username:
            print(f"Error descifrando username de {addr}")
            client_sock.close()
            return

        username = username.strip()
        if not username:
            client_sock.close()
            return

        with clients_lock:
            clients[client_sock] = username

        join_msg = f"{username} se ha unido."
        print(join_msg)
        broadcast(join_msg, sender_sock=client_sock)

        # Loop para recibir mensajes cifrados
        while True:
            encrypted_data = client_sock.recv(4096)
            if not encrypted_data:
                break
                
            text = AESEncryption.decrypt(encrypted_data)
            if not text:
                print(f"Error descifrando mensaje de {username}")
                continue
                
            text = text.strip()
            if text.lower() == 'exit':
                break

            message = f"{username}: {text}"
            print(message)
            broadcast(message, sender_sock=client_sock)

    except Exception as e:
        print(f"Error con {addr}: {e}")

    finally:
        with clients_lock:
            username = clients.pop(client_sock, None)
        if username:
            leave_msg = f"{username} se ha desconectado."
            print(leave_msg)
            broadcast(leave_msg, sender_sock=client_sock)
        remove_client(client_sock)

def run_server():
    print("=== SERVIDOR - VERSIÓN 1.1 (AES + SHA256) ===")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    
    print(f"Servidor iniciado en {HOST}:{PORT}")
    print("Algoritmo: AES-256-GCM")
    print("Derivación: PBKDF2-HMAC-SHA256")
    print("Presiona Ctrl+C para detener\n")

    try:
        while True:
            client_sock, client_addr = server_socket.accept()
            print(f"Nueva conexión: {client_addr}")
            threading.Thread(
                target=handle_client, 
                args=(client_sock, client_addr), 
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        server_socket.close()

if __name__ == '__main__':
    run_server()