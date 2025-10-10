import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'localhost'
PORT = 9999

clients = {}  # {socket: username}  - YA NO guardamos public_key del cliente
clients_lock = threading.Lock()

DEBUG = True  # Cambia a False para ocultar tiempos

# === Cargar llaves del servidor ===
def load_server_keys():
    with open("keys/server_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("keys/server_public.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return private_key, public_key


def encrypt_message(public_key, message: str):
    """Cifra un mensaje con la llave pública dada."""
    start = time.perf_counter()
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    end = time.perf_counter()
    if DEBUG:
        print(f"[DEBUG] Cifrado en {end - start:.6f} segundos")
    return encrypted


def decrypt_message(private_key, ciphertext: bytes):
    """Descifra un mensaje con la llave privada del servidor."""
    start = time.perf_counter()
    message = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode('utf-8')
    end = time.perf_counter()
    if DEBUG:
        print(f"[DEBUG] Descifrado en {end - start:.6f} segundos")
    return message


def broadcast(message, sender_sock=None):
    """Envía un mensaje en TEXTO PLANO a todos los clientes (excepto al remitente)."""
    start = time.perf_counter()
    with clients_lock:
        for sock, username in list(clients.items()):
            if sock is sender_sock:
                continue
            try:
                # ENVIAR SIN CIFRAR - texto plano
                sock.sendall(message.encode('utf-8'))
            except Exception as e:
                if DEBUG:
                    print(f"[DEBUG] Error enviando a {username}: {e}")
                remove_client(sock)
    end = time.perf_counter()
    if DEBUG:
        print(f"[DEBUG] Broadcast en {end - start:.6f} segundos")


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

        # ELIMINADO: Recepción de llave pública del cliente
        # client_public_pem = client_sock.recv(2048)
        # client_public_key = serialization.load_pem_public_key(client_public_pem)

        # Enviar la llave pública del servidor al cliente
        with open("keys/server_public.pem", "rb") as f:
            client_sock.sendall(f.read())

        # Guardar solo el username (ya no la public_key)
        with clients_lock:
            clients[client_sock] = username

        join_msg = f"{username} se ha unido."
        print(join_msg)
        broadcast(join_msg, sender_sock=client_sock)

        # Ciclo de recepción de mensajes cifrados del cliente
        while True:
            encrypted_data = client_sock.recv(4096)
            if not encrypted_data:
                break

            # Descifrar mensaje del cliente (con server_private)
            text = decrypt_message(server_private_key, encrypted_data)
            if text.lower() == 'exit':
                break

            print(f"{username}: {text}")
            # Transmitir SIN cifrar a otros clientes
            broadcast(f"{username}: {text}", sender_sock=client_sock)

    except Exception as e:
        print(f"Error con {addr}: {e}")
        if DEBUG:
            import traceback
            traceback.print_exc()

    finally:
        with clients_lock:
            user = clients.pop(client_sock, None)
        if user:
            leave_msg = f"{user} se ha desconectado."
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
    print("Modo: 2 llaves (servidor privada + servidor pública)")
    print("→ Clientes envían mensajes CIFRADOS")
    print("→ Servidor envía mensajes en TEXTO PLANO")

    try:
        while True:
            client_sock, client_addr = sock.accept()
            print(f"Nueva conexión desde {client_addr}")
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