# src/ui/login_window.py
import os
import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton,
    QMessageBox, QSpacerItem, QSizePolicy
)
from PySide6.QtCore import Qt

from core.auth import login
from ui.main_window import MainWindow

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Chat privado")
        self.resize(360, 480)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(60, 80, 60, 80)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignCenter)

        title_label = QLabel("Iniciar sesión")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #2E4053;")
        title_label.setAlignment(Qt.AlignCenter)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Usuario")
        self.user_input.setMinimumHeight(35)
        self.user_input.setStyleSheet("padding: 6px; font-size: 14px;")

        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Contraseña")
        self.pass_input.setEchoMode(QLineEdit.Password)
        self.pass_input.setMinimumHeight(35)
        self.pass_input.setStyleSheet("padding: 6px; font-size: 14px;")

        login_button = QPushButton("Entrar")
        login_button.setMinimumHeight(40)
        login_button.setStyleSheet("""
            QPushButton {
                background-color: #3498DB;
                color: white;
                border-radius: 6px;
                font-size: 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2980B9;
            }
        """)
        login_button.clicked.connect(self.handle_login)

        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        layout.addWidget(title_label)
        layout.addWidget(self.user_input)
        layout.addWidget(self.pass_input)
        layout.addWidget(login_button)
        layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        self.setLayout(layout)

    def handle_login(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text().strip()

        if not username or not password:
            QMessageBox.warning(self, "Campos vacíos", "Por favor, completa todos los campos.")
            return

        # Verificar credenciales con el módulo core/auth.py
        if login(username, password):
            QMessageBox.information(self, "Bienvenido", f"Hola {username}")
            self.close()

            from ui.main_window import MainWindow

            self.main_window = MainWindow(username)
            self.main_window.show()

        else:
            QMessageBox.critical(self, "Error", "Usuario o contraseña incorrectos.") 

    def open_main_menu(self):
        from ui.main_window import MainWindow
        self.hide()
        self.main_menu = MainWindow()
        self.main_menu.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LoginWindow()
    window.show()
    sys.exit(app.exec())
