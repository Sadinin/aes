import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QFileDialog
from SAES import SAES


class SAESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.aes = SAES()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-AES 加密解密')
        self.setGeometry(100, 100, 400, 200)

        layout = QVBoxLayout()

        # 明文输入框
        self.plain_text_label = QLabel('明文(16位二进制):')
        self.plain_text_input = QLineEdit()
        layout.addWidget(self.plain_text_label)
        layout.addWidget(self.plain_text_input)

        # 密文输入框
        self.cipher_text_label = QLabel('密文(16位二进制):')
        self.cipher_text_input = QLineEdit()
        layout.addWidget(self.cipher_text_label)
        layout.addWidget(self.cipher_text_input)

        # 密钥输入框
        self.key_label = QLabel('密钥(16位二进制):')
        self.key_input = QLineEdit()
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)

        # 加密按钮
        self.encrypt_button = QPushButton('加密')
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        # 解密按钮
        self.decrypt_button = QPushButton('解密')
        self.decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_button)

        # 结果显示
        self.result_label = QLabel('')
        layout.addWidget(self.result_label)
        self.setLayout(layout)

        # 清空按钮
        self.clear_button = QPushButton('清空')
        self.clear_button.clicked.connect(self.clear)
        layout.addWidget(self.clear_button)

        # 导出按钮
        self.export_button = QPushButton('导出')
        self.export_button.clicked.connect(self.export_data)
        layout.addWidget(self.export_button)

    def encrypt(self):
        plaintext = self.plain_text_input.text()
        key = self.key_input.text()

        if plaintext == '' or key == '':
            QMessageBox.warning(self, '警告', '请输入明文和密钥')
            return

        try:
            plaintext = [[int(plaintext[0:4], 2), int(plaintext[8:12], 2)],
                         [int(plaintext[4:8], 2), int(plaintext[12:16], 2)]]
            key = int(key, 2)
        except ValueError:
            QMessageBox.warning(self, '警告', '请输入正确的二进制数字')
            return

        ciphertext = self.aes.encrypt(plaintext, key)
        ciphertext_str = ''.join([f'{ciphertext[i][j]:04b}' for i in range(2) for j in range(2)])

        ciphertext_binary = ciphertext_str[0:4] + ciphertext_str[8:12] + ciphertext_str[4:8] + ciphertext_str[12:16]
        self.cipher_text_input.setText(ciphertext_binary)
        self.result_label.setText(f'加密成功 密文：{ciphertext_binary}')

    def decrypt(self):
        ciphertext = self.cipher_text_input.text()
        key = self.key_input.text()

        if ciphertext == '' or key == '':
            QMessageBox.warning(self, '警告', '请输入密文和密钥')
            return

        try:
            ciphertext = [[int(ciphertext[0:4], 2), int(ciphertext[8:12], 2)],
                         [int(ciphertext[4:8], 2), int(ciphertext[12:16], 2)]]
            key = int(key, 2)
        except ValueError:
            QMessageBox.warning(self, '警告', '请输入正确的二进制数字')
            return

        plaintext = self.aes.decrypt(ciphertext, key)

        plaintext_str = ''.join([f'{plaintext[i][j]:04b}' for i in range(2) for j in range(2)])

        plaintext_binary = plaintext_str[0:4] + plaintext_str[8:12] + plaintext_str[4:8] + plaintext_str[12:16]
        self.plain_text_input.setText(plaintext_binary)
        self.result_label.setText(f'解密成功 明文：{plaintext_binary}')

    def export_data(self):
        plaintext = self.plain_text_input.text()
        ciphertext = self.cipher_text_input.text()
        key = self.key_input.text()

        if plaintext == '' and ciphertext == '' and key == '':
            QMessageBox.warning(self, '警告', '没有数据可以导出')
            return

        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        file_name, _ = QFileDialog.getSaveFileName(self, "保存文件", "", "Text Files (*.txt)", options=options)

        if file_name:
            with open(file_name, 'w') as file:
                file.write(f'明文: {plaintext}\n')
                file.write(f'密钥: {key}\n')
                file.write(f'密文: {ciphertext}\n')
            QMessageBox.information(self, '提示', '数据已成功导出')

    def clear(self):
        self.plain_text_input.clear()
        self.cipher_text_input.clear()
        self.key_input.clear()
        self.result_label.clear()

def main():
    app = QApplication(sys.argv)
    window = SAESApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()