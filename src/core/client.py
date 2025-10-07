import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'localhost'
PORT = 9999

def load_client_keys():
    with open("keys/client_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("keys/client_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def encrypt_message(public_key, message: str):
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def receive_messages(sock, private_key):
    """Hilo que escucha los mensajes cifrados del servidor."""
    while True:
        try:
            encrypted_data = sock.recv(4096)
            if not encrypted_data:
                print("\n[Sistema] Conexión cerrada por el servidor.")
                break
            msg = decrypt_message(private_key, encrypted_data)
            print(f"\n{msg}")
        except Exception:
            print("\n[Sistema] Error recibiendo mensaje.")
            break

def send_messages(sock, server_public_key):
    """Hilo que envía mensajes cifrados."""
    while True:
        msg = input()
        if not msg:
            continue

        encrypted = encrypt_message(server_public_key, msg)
        sock.sendall(encrypted)

        if msg.lower() == 'exit':
            break
        print(f"[Tú] {msg}")

def run_client():
    client_private, client_public = load_client_keys()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    username = input("Nombre de usuario: ").strip()
    while not username:
        username = input("Nombre vacío. Introduce tu nombre de usuario: ").strip()
    sock.sendall(username.encode('utf-8'))

    # Enviar llave pública del cliente
    with open("keys/client_public.pem", "rb") as f:
        sock.sendall(f.read())

    # Recibir llave pública del servidor
    server_public_pem = sock.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_pem)

    print("Conectado al chat cifrado. Escribe mensajes (exit para salir).")

    recv_thread = threading.Thread(target=receive_messages, args=(sock, client_private), daemon=True)
    recv_thread.start()
    send_messages(sock, server_public_key)

    sock.close()
    print("Desconectado.")

if __name__ == '__main__':
    run_client()
