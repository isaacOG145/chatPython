import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'localhost'
PORT = 9999

clients = {}  # {socket: (username, public_key)}
clients_lock = threading.Lock()

# === Cargar llaves del servidor ===
def load_server_keys():
    with open("keys/server_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("keys/server_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key

def encrypt_message(public_key, message: str):
    """Cifra un mensaje con la llave pública dada."""
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(private_key, ciphertext: bytes):
    """Descifra un mensaje con la llave privada del servidor."""
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')

def broadcast(message, sender_sock=None):
    """Envía un mensaje cifrado a todos los clientes (excepto al remitente)."""
    with clients_lock:
        for sock, (username, pubkey) in list(clients.items()):
            if sock is sender_sock:
                continue
            try:
                encrypted = encrypt_message(pubkey, message)
                sock.sendall(encrypted)
            except Exception:
                remove_client(sock)

def remove_client(client_sock):
    """Elimina al cliente del diccionario y cierra su socket."""
    with clients_lock:
        clients.pop(client_sock, None)
    try:
        client_sock.close()
    except:
        pass

def handle_client(client_sock, addr, server_private_key, server_public_key):
    try:
        # Recibir nombre de usuario
        username = client_sock.recv(1024).decode('utf-8').strip()
        if not username:
            client_sock.close()
            return

        # Recibir llave pública del cliente
        client_public_pem = client_sock.recv(2048)
        client_public_key = serialization.load_pem_public_key(client_public_pem)

        # Enviar la llave pública del servidor
        with open("keys/server_public.pem", "rb") as f:
            client_sock.sendall(f.read())

        with clients_lock:
            clients[client_sock] = (username, client_public_key)

        join_msg = f"{username} se ha unido."
        print(join_msg)
        broadcast(join_msg, sender_sock=client_sock)

        # Ciclo de recepción
        while True:
            encrypted_data = client_sock.recv(4096)
            if not encrypted_data:
                break

            text = decrypt_message(server_private_key, encrypted_data)
            if text.lower() == 'exit':
                break

            print(f"{username}: {text}")
            broadcast(f"{username}: {text}", sender_sock=client_sock)

    except Exception as e:
        print(f"Error con {addr}: {e}")

    finally:
        with clients_lock:
            user = clients.pop(client_sock, None)
        if user:
            leave_msg = f"{user[0]} se ha desconectado."
            print(leave_msg)
            broadcast(leave_msg)
        remove_client(client_sock)

def run_server():
    server_private, server_public = load_server_keys()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(10)
    print(f"Servidor iniciado en {HOST}:{PORT}")

    try:
        while True:
            client_sock, client_addr = sock.accept()
            threading.Thread(
                target=handle_client,
                args=(client_sock, client_addr, server_private, server_public),
                daemon=True
            ).start()
    except KeyboardInterrupt:
        print("Servidor detenido.")
    finally:
        sock.close()

if __name__ == '__main__':
    run_server()
