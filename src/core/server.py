import time
import socket
import threading
from cryptography.fernet import Fernet

HOST = 'localhost'
PORT = 9999

# mapa socket -> username
clients = {}
clients_lock = threading.Lock()

DEBUG = True 

with open("keys/symmetric.key", "rb") as f:
    fernet = Fernet(f.read())

def encrypt(msg: str) -> bytes:
    start = time.perf_counter()
    token = fernet.encrypt(msg.encode('utf-8'))
    end = time.perf_counter()
    if DEBUG:
        print(f"[DEBUG] Cifrado en {end - start:.6f} segundos")
    return token

def decrypt(token: bytes) -> str:
    start = time.perf_counter()
    msg = fernet.decrypt(token).decode('utf-8')
    end = time.perf_counter()
    if DEBUG:
        print(f"[DEBUG] Descifrado en {end - start:.6f} segundos")
    return msg

def broadcast(message: str, sender_sock=None):
    """Envía message (ya como texto normal) cifrado a todos los clientes excepto el remitente."""
    encrypted_msg = encrypt(message)
    with clients_lock:
        for client in list(clients.keys()):
            if client is sender_sock:
                continue
            try:
                client.sendall(encrypted_msg)
            except Exception:
                remove_client(client)

def remove_client(client_sock):
    """Elimina y cierra el socket del cliente (si existe)."""
    with clients_lock:
        clients.pop(client_sock, None)
    try:
        client_sock.close()
    except:
        pass

def handle_client(client_sock, addr):
    try:
        # Primer mensaje esperado: el nombre de usuario (cifrado)
        username = decrypt(client_sock.recv(1024)).strip()
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
            data = client_sock.recv(1024)
            if not data:
                break
            text = decrypt(data).strip()
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
        try:
            client_sock.close()
        except:
            pass

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(10)
    print(f"Servidor iniciado en {HOST}:{PORT}. Esperando conexiones...")

    try:
        while True:
            client_sock, client_addr = server_socket.accept()
            print(f"Conexión entrante desde {client_addr}")
            threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True).start()
    except KeyboardInterrupt:
        print("Servidor detenido por usuario.")
    finally:
        with clients_lock:
            for c in list(clients.keys()):
                try:
                    c.close()
                except:
                    pass
        server_socket.close()

if __name__ == '__main__':
    run_server()
