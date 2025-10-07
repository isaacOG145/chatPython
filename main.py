import os
import subprocess
import sys
import socket

HOST = 'localhost'
PORT = 9999

# Detectar ruta base del proyecto
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_PATH = os.path.join(BASE_DIR, "src", "core", "server.py")
CLIENT_PATH = os.path.join(BASE_DIR, "src", "core", "client.py")

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_server_running(host=HOST, port=PORT):
    """Devuelve True si hay algo escuchando en ese host y puerto."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, socket.timeout):
            return False

def main():
    clear_console()
    print("Bienvenido al Chat Local")
    print("----------------------------")
    print("1. Crear una sala (iniciar servidor)")
    print("2. Unirse a una sala (cliente)")
    print("3. Salir")
    print("----------------------------")

    option = input("Selecciona una opción (1-3): ").strip()

    if option == "1":
        if is_server_running():
            print("\nYa hay un servidor corriendo en este puerto (localhost:9999).")
            print("   No se puede iniciar otro servidor.")
        else:
            print("\nIniciando servidor...\n")
            subprocess.run([sys.executable, SERVER_PATH])
    elif option == "2":
        print("\nConectando al servidor...\n")
        subprocess.run([sys.executable, CLIENT_PATH])
    elif option == "3":
        print("Saliendo del programa.")
        sys.exit(0)
    else:
        print("Opción inválida. Intenta de nuevo.")
        input("Presiona ENTER para continuar...")
        main()  # volver a mostrar el menú

if __name__ == "__main__":
    main()
