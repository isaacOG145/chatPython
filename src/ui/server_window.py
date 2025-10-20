# src/ui/server_window.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton
from PySide6.QtCore import Qt, QTimer
import subprocess, sys, os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_PATH = os.path.join(BASE_DIR, "core", "server.py")

class ServerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Servidor activo")
        self.resize(600, 400)
        self.setup_ui()
        self.start_server()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignTop)
        layout.setContentsMargins(20, 20, 20, 20)

        label = QLabel("Servidor en ejecución (puerto 9999)")
        label.setStyleSheet("font-size: 18px; font-weight: bold; color: #2E4053;")

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setStyleSheet("background: #F4F6F7; font-family: monospace; font-size: 13px;")

        self.stop_button = QPushButton("Detener servidor")
        self.stop_button.setStyleSheet("background-color: #E74C3C; color: white; font-weight: bold; border-radius: 8px;")
        self.stop_button.clicked.connect(self.stop_server)

        layout.addWidget(label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.stop_button)
        self.setLayout(layout)

    def start_server(self):
        """Inicia el servidor y redirige su salida."""
        self.process = subprocess.Popen(
            [sys.executable, SERVER_PATH],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.read_output)
        self.timer.start(300)

    def read_output(self):
        """Lee la salida del servidor en tiempo real."""
        if self.process.poll() is None:
            output = self.process.stdout.readline()
            if output:
                self.log_area.append(output.strip())

    def stop_server(self):
        """Detiene el servidor."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.log_area.append("Servidor detenido.")
