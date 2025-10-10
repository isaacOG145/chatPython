#!/usr/bin/env python3
"""
VERSIÓN 1.0 - RSA + SHA256
Servidor con cifrado asimétrico RSA y hashing SHA256.
Solo usa 2 llaves (servidor).
"""

import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'localhost'
PORT = 9999

clients = {}  # {socket: username}
clients_lock = threading.Lock()

DEBUG = True

def load_server_keys():
    """Carga las llaves RSA del servidor."""
    with open("keys/server_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("keys/server_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def encrypt_message(public_key, message: str):
    """Cifra mensaje con RSA OAEP-SHA256."""
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, ciphertext: bytes):
    """Descifra mensaje con RSA OAEP-SHA256."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def broadcast(message, sender_sock=None):
    """Envía mensaje en texto plano a todos los clientes."""
    with clients_lock:
        for sock, username in list(clients.items()):
            if sock is sender_sock:
                continue
            try:
                sock.sendall(message.encode('utf-8'))
            except Exception:
                remove_client(sock)

def remove_client(client_sock):
    """Elimina cliente y cierra conexión."""
    with clients_lock:
        clients.pop(client_sock, None)
    try:
        client_sock.close()
    except:
        pass

def handle_client(client_sock, addr, server_private_key, server_public_key):
    """Maneja la conexión con un cliente."""
    try:
        # Recibir nombre de usuario
        username = client_sock.recv(1024).decode('utf-8').strip()
        if not username:
            client_sock.close()
            return

        # Enviar llave pública del servidor
        with open("keys/server_public.pem", "rb") as f:
            client_sock.sendall(f.read())

        # Registrar cliente
        with clients_lock:
            clients[client_sock] = username

        join_msg = f"{username} se ha unido al chat."
        print(join_msg)
        broadcast(join_msg, sender_sock=client_sock)

        # Ciclo de recepción de mensajes cifrados
        while True:
            encrypted_data = client_sock.recv(4096)
            if not encrypted_data:
                break

            # Descifrar mensaje del cliente
            text = decrypt_message(server_private_key, encrypted_data)
            if text.lower() == 'exit':
                break

            print(f"{username}: {text}")
            # Retransmitir en texto plano
            broadcast(f"{username}: {text}", sender_sock=client_sock)

    except Exception as e:
        print(f"Error con {addr}: {e}")

    finally:
        # Limpiar cliente desconectado
        with clients_lock:
            user = clients.pop(client_sock, None)
        if user:
            leave_msg = f"{user} se ha desconectado."
            print(leave_msg)
            broadcast(leave_msg)
        remove_client(client_sock)

def run_server():
    print("=== SERVIDOR - VERSIÓN 1.0 (RSA + SHA256) ===")
    
    # Cargar llaves RSA
    server_private, server_public = load_server_keys()
    
    # Configurar socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(10)
    
    print(f"🚀 Servidor iniciado en {HOST}:{PORT}")
    print("🔐 Algoritmo: RSA 2048 + SHA256")
    print("🗝️  Llaves: 2 (servidor)")
    print("📨 Clientes → Servidor: CIFRADO")
    print("📨 Servidor → Clientes: TEXTO PLANO")
    print("⏹️  Presiona Ctrl+C para detener\n")

    try:
        while True:
            client_sock, client_addr = sock.accept()
            print(f"✅ Nueva conexión: {client_addr}")
            
            threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, server_private, server_public),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
    finally:
        sock.close()

if __name__ == '__main__':
    run_server()