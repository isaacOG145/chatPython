import os
import subprocess
import sys
import socket

HOST = 'localhost'
PORT = 9999

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_PATH = os.path.join(BASE_DIR, "src", "core", "server.py")
LOGIN_PATH = os.path.join(BASE_DIR, "src", "ui", "login_window.py")

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def is_server_running(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, port))
            return True
        except (ConnectionRefusedError, socket.timeout):
            return False

def main():
    subprocess.run([sys.executable, LOGIN_PATH])
    
if __name__ == "__main__":
    main()
