import socket
import threading
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = 'localhost'
PORT = 9999

def encrypt_message(public_key, message: str):
    """Cifra un mensaje con la llave pública del servidor."""
    return public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def receive_messages(sock):
    """Hilo que escucha los mensajes SIN cifrar del servidor."""
    while True:
        try:
            message = sock.recv(4096).decode('utf-8')
            if not message:
                print("\n[Sistema] Conexión cerrada por el servidor.")
                break
            print(f"\n{message}")
        except Exception as e:
            print(f"\n[Sistema] Error recibiendo mensaje: {e}")
            break

def send_messages(sock, server_public_key):
    """Hilo que envía mensajes cifrados al servidor."""
    while True:
        msg = input()
        if not msg:
            continue

        # Cifrar mensaje para el servidor
        encrypted = encrypt_message(server_public_key, msg)
        sock.sendall(encrypted)

        if msg.lower() == 'exit':
            break
        print(f"[Tú] {msg}")

def run_client():
    # Conectar al servidor
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Enviar nombre de usuario
    username = input("Nombre de usuario: ").strip()
    while not username:
        username = input("Nombre vacío. Introduce tu nombre de usuario: ").strip()
    sock.sendall(username.encode('utf-8'))

    # Recibir llave pública del servidor
    server_public_pem = sock.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_pem)

    print("Conectado al chat cifrado. Escribe mensajes (exit para salir).")
    print("→ Los mensajes que envías están cifrados")
    print("→ Los mensajes que recibes están en texto plano")

    # Iniciar hilo para recibir mensajes (sin cifrado)
    recv_thread = threading.Thread(target=receive_messages, args=(sock,), daemon=True)
    recv_thread.start()
    
    # Enviar mensajes (cifrados al servidor)
    send_messages(sock, server_public_key)

    sock.close()
    print("Desconectado.")

if __name__ == '__main__':
    run_client()