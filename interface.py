from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit,
    QPushButton, QFileDialog, QWidget, QMessageBox, QPlainTextEdit
)
from stegano import lsb
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
import base64
import os
import sys

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


class SteganographyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Steganography Tool")
        self.setGeometry(200, 200, 600, 400)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.encrypt_tab = QWidget()
        self.init_encrypt_tab()
        self.tabs.addTab(self.encrypt_tab, "Зашифровать")

        self.decrypt_tab = QWidget()
        self.init_decrypt_tab()
        self.tabs.addTab(self.decrypt_tab, "Расшифровать")

    def init_encrypt_tab(self):
        layout = QVBoxLayout()

        self.load_image_button = QPushButton("Загрузить изображение для шифрования")
        self.load_image_button.clicked.connect(self.load_encrypt_image)
        layout.addWidget(self.load_image_button)

        self.encrypt_file_label = QLabel("Файл не выбран")
        layout.addWidget(self.encrypt_file_label)

        self.message_label = QLabel("Введите сообщение:")
        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText("Введите текст...")
        layout.addWidget(self.message_label)
        layout.addWidget(self.message_input)

        self.password_label = QLabel("Введите пароль:")
        self.encrypt_password_input = QLineEdit()
        self.encrypt_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.encrypt_password_input)

        self.encrypt_button = QPushButton("Зашифровать")
        self.encrypt_button.clicked.connect(self.encrypt_message)
        layout.addWidget(self.encrypt_button)

        self.encrypt_tab.setLayout(layout)

    def init_decrypt_tab(self):
        layout = QVBoxLayout()

        self.load_decrypt_image_button = QPushButton("Загрузить изображение для расшифровки")
        self.load_decrypt_image_button.clicked.connect(self.load_decrypt_image)
        layout.addWidget(self.load_decrypt_image_button)

        self.decrypt_file_label = QLabel("Файл не выбран")
        layout.addWidget(self.decrypt_file_label)

        self.password_label = QLabel("Введите пароль:")
        self.decrypt_password_input = QLineEdit()
        self.decrypt_password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_label)
        layout.addWidget(self.decrypt_password_input)

        self.decrypt_button = QPushButton("Расшифровать")
        self.decrypt_button.clicked.connect(self.decrypt_message)
        layout.addWidget(self.decrypt_button)

        self.decrypted_text_label = QLabel("Расшифрованное сообщение:")
        self.decrypted_text_display = QPlainTextEdit()
        self.decrypted_text_display.setReadOnly(True)
        layout.addWidget(self.decrypted_text_label)
        layout.addWidget(self.decrypted_text_display)

        self.decrypt_tab.setLayout(layout)

    def load_encrypt_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите изображение для шифрования", "", "Images (*.png *.jpeg *.jpg)")
        if file_path:
            self.encrypt_file_path = file_path
            self.encrypt_file_label.setText(f"Выбранный файл: {file_path}")
        else:
            self.encrypt_file_path = None
            self.encrypt_file_label.setText("Файл не выбран")

    def load_decrypt_image(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Выберите изображение для расшифровки", "", "Images (*.png *.jpeg *.jpg)")
        if file_path:
            self.decrypt_file_path = file_path
            self.decrypt_file_label.setText(f"Выбранный файл: {file_path}")
        else:
            self.decrypt_file_path = None
            self.decrypt_file_label.setText("Файл не выбран")

    def encrypt_message(self):
        if not hasattr(self, 'encrypt_file_path') or not self.encrypt_file_path:
            QMessageBox.warning(self, "Ошибка", "Сначала загрузите изображение для шифрования.")
            return

        message = self.message_input.toPlainText().strip()
        password = self.encrypt_password_input.text().strip()

        if not message or not password:
            QMessageBox.warning(self, "Ошибка", "Введите сообщение и пароль.")
            return

        save_path, _ = QFileDialog.getSaveFileName(self, "Сохранить изображение как", "", "PNG Files (*.png)")
        if not save_path:
            return

        try:
            salt = os.urandom(16)
            key = generate_key_from_password(password, salt)
            cipher = Fernet(key)
            encrypted_message = cipher.encrypt(message.encode('utf-8'))
            message_with_salt = salt + encrypted_message

            lsb.hide(self.encrypt_file_path, message_with_salt.decode('latin1')).save(save_path)
            QMessageBox.information(self, "Успех", f"Сообщение зашифровано и сохранено как {save_path}.")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка: {e}")

    def decrypt_message(self):
        if not hasattr(self, 'decrypt_file_path') or not self.decrypt_file_path:
            QMessageBox.warning(self, "Ошибка", "Сначала загрузите изображение для расшифровки.")
            return

        password = self.decrypt_password_input.text().strip()

        if not password:
            QMessageBox.warning(self, "Ошибка", "Введите пароль.")
            return

        try:
            hidden_message_with_salt = lsb.reveal(self.decrypt_file_path)
            if not hidden_message_with_salt:
                raise ValueError("Сообщение не найдено.")

            hidden_message_with_salt = hidden_message_with_salt.encode('latin1')
            extracted_salt = hidden_message_with_salt[:16]
            extracted_encrypted_message = hidden_message_with_salt[16:]

            key = generate_key_from_password(password, extracted_salt)
            cipher = Fernet(key)

            decrypted_message = cipher.decrypt(extracted_encrypted_message).decode('utf-8')
            self.decrypted_text_display.setPlainText(decrypted_message)
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Произошла ошибка: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SteganographyApp()
    window.show()
    sys.exit(app.exec())
