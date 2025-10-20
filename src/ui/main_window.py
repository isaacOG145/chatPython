#!/usr/bin/env python3
import sys
import os
import subprocess
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
)
from PySide6.QtCore import Qt

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PATH = os.path.join(BASE_DIR, "core", "server.py")
CLIENT_UI_PATH = os.path.join(BASE_DIR, "ui", "chat_window.py")  # Nuevo
sys.path.append(BASE_DIR)

from ui.chat_window import ChatWindow


class MainWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.setWindowTitle("Menú principal - Chat Seguro")
        self.resize(400, 300)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)

        title = QLabel(f"Bienvenido, {self.username}")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold;")

        start_server_btn = QPushButton("🟢 Iniciar servidor")
        join_chat_btn = QPushButton("🔵 Unirse al chat")

        start_server_btn.setMinimumHeight(40)
        join_chat_btn.setMinimumHeight(40)

        start_server_btn.clicked.connect(self.start_server)
        join_chat_btn.clicked.connect(self.open_chat)

        layout.addWidget(title)
        layout.addSpacing(20)
        layout.addWidget(start_server_btn)
        layout.addWidget(join_chat_btn)

        self.setLayout(layout)

    def start_server(self):
        try:
            subprocess.Popen([sys.executable, SERVER_PATH])
            QMessageBox.information(self, "Servidor iniciado", "El servidor se ha iniciado correctamente.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"No se pudo iniciar el servidor:\n{e}")

    def open_chat(self):
        self.hide()
        self.chat_window = ChatWindow(self.username)
        self.chat_window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    username = "Isaac"  # Simulación temporal
    window = MainWindow(username)
    window.show()
    sys.exit(app.exec())
