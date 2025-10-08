import socket
import threading
from cryptography.fernet import Fernet

HOST = 'localhost'
PORT = 9999

# cargar clave simétrica
with open("keys/symmetric.key", "rb") as f:
    fernet = Fernet(f.read())

def encrypt(msg: str) -> bytes:
    return fernet.encrypt(msg.encode('utf-8'))

def decrypt(token: bytes) -> str:
    return fernet.decrypt(token).decode('utf-8')

def receive_messages(sock):
    """Escucha mensajes del servidor (cifrados) y los imprime."""
    while True:
        try:
            data = sock.recv(1024)
            if not data:
                print("\n[Sistema] Conexión cerrada por el servidor.")
                break
            message = decrypt(data)
            print("\n" + message)
        except Exception:
            print("\n[Sistema] Error recibiendo datos o descifrando mensaje.")
            break

def send_messages(sock):
    """Lee del input y envía al servidor (cifrado)."""
    while True:
        try:
            msg = input()
            if not msg:
                continue

            sock.sendall(encrypt(msg))

            if msg.strip().lower() == 'exit':
                break

            print(f"[Tú] {msg}")
        except Exception:
            print("[Sistema] Error enviando mensaje.")
            break

def run_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    username = input("Nombre de usuario: ").strip()
    while not username:
        username = input("Nombre vacío. Introduce tu nombre de usuario: ").strip()
    sock.sendall(encrypt(username))

    print("Conectado al chat. Escribe mensajes (escribe 'exit' para salir).")

    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()

    send_messages(sock)

    try:
        sock.close()
    except:
        pass
    print("Desconectado.")

if __name__ == '__main__':
    run_client()
