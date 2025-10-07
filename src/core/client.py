import socket
import threading

HOST = 'localhost'
PORT = 9999

def receive_messages(sock):
    """Escucha mensajes del servidor y los imprime."""
    while True:
        try:
            data = sock.recv(1024).decode('utf-8')
            if not data:
                print("\n[Sistema] Conexión cerrada por el servidor.")
                break
            print("\n" + data)
        except Exception:
            print("\n[Sistema] Error recibiendo datos.")
            break

def send_messages(sock):
    """Lee del input y envía al servidor. Muestra [Tú] al enviar."""
    while True:
        try:
            msg = input()
            if not msg:
                continue

            sock.sendall(msg.encode('utf-8'))

            if msg.strip().lower() == 'exit':
                break

            # Mostrar tu propio mensaje localmente
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
    sock.sendall(username.encode('utf-8'))

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
