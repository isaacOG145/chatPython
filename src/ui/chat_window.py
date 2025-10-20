# src/ui/chat_window.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel, QHBoxLayout
from PySide6.QtCore import Qt, QThread, Signal
import socket, base64, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = 'localhost'
PORT = 9999

with open("keys/symmetric.key", "rb") as f:
    AES_KEY = base64.urlsafe_b64decode(f.read())

aesgcm = AESGCM(AES_KEY)

class ReceiveThread(QThread):
    message_received = Signal(str)

    def __init__(self, sock):
        super().__init__()
        self.sock = sock

    def run(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                msg = self.decrypt(data)
                if msg:
                    self.message_received.emit(msg)
            except:
                break

    def decrypt(self, encrypted_data):
        try:
            nonce, ciphertext = encrypted_data[:12], encrypted_data[12:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except:
            return None

class ChatWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle(f"Chat - {username}")
        self.resize(600, 500)
        self.setup_ui()
        self.connect_to_server()

    def setup_ui(self):
        layout = QVBoxLayout()

        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)

        input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Escribe un mensaje...")
        send_button = QPushButton("Enviar")
        send_button.clicked.connect(self.send_message)

        input_layout.addWidget(self.message_input)
        input_layout.addWidget(send_button)

        layout.addWidget(QLabel(f"Conectado como: {self.username}"))
        layout.addWidget(self.chat_area)
        layout.addLayout(input_layout)
        self.setLayout(layout)

    def connect_to_server(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        # Enviar nombre de usuario cifrado
        self.sock.sendall(self.encrypt(self.username))
        self.chat_area.append("Conectado al servidor.\n")

        self.receiver = ReceiveThread(self.sock)
        self.receiver.message_received.connect(self.display_message)
        self.receiver.start()

    def encrypt(self, message):
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode("utf-8"), None)
        return nonce + ciphertext

    def display_message(self, msg):
        self.chat_area.append(msg)

    def send_message(self):
        msg = self.message_input.text().strip()
        if not msg:
            return
        self.sock.sendall(self.encrypt(msg))
        self.chat_area.append(f"Tú: {msg}")
        self.message_input.clear()
