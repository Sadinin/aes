import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox



def SAES():
    pass


class SAES:
    def __init__(self):
        # 初始化S盒和逆S盒
        self.S_BOX = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]

        self.INV_S_BOX = [
            [0xA, 0x5, 0x9, 0xB],
            [0x1, 0x7, 0x8, 0xF],
            [0x6, 0x0, 0x2, 0x3],
            [0xC, 0x4, 0xD, 0xE]
        ]

    def _rotate_nibbles(self, word):
        """将一个8位字的半字节进行循环左移"""
        return ((word << 4) | (word >> 4)) & 0xFF

    def _sub_nibbles(self, word, s_box):
        """使用给定的S-Box替换8bit的数据。"""
        high_nibble = (word >> 4) & 0x0F
        low_nibble = word & 0x0F
        new_high_nibble = s_box[high_nibble >> 2][high_nibble & 0x03]
        new_low_nibble = s_box[low_nibble >> 2][low_nibble & 0x03]
        return (new_high_nibble << 4) | new_low_nibble

    def _key_expansion(self, key):
        """Key expansion for S-AES."""
        w = [(key >> 8) & 0xFF, key & 0xFF]
        temp1 = 0x80
        temp2 = 0x30
        expanded_keys = []
        for i in range(2):
            g_w1 = self._sub_nibbles(self._rotate_nibbles(w[1]), self.S_BOX)
            w2 = w[0] ^ temp1 ^ g_w1
            w3 = w2 ^ w[1]
            g_w3 = self._sub_nibbles(self._rotate_nibbles(w3), self.S_BOX)
            w4 = w2 ^ temp2 ^ g_w3
            w5 = w4 ^ w3
            expanded_keys.extend([w[0], w[1], w2, w3, w4, w5])
            w = [w2, w3]
        return expanded_keys

    def _add_round_key(self, state, round_key):
        """轮密钥加操作"""
        for i in range(2):
            for j in range(2):
                state[i][j] ^= round_key[i][j]
        return state

    def _sub_bytes(self, state, s_box):
        for i in range(2):
            for j in range(2):
                state[i][j] = self._sub_nibbles(state[i][j], s_box)
        return state

    def _shift_rows(self, state):
        for i in range(2):
            state[i] = state[i][i:] + state[i][:i]
        return state

    def _mix_columns(self, state):
        for i in range(2):
            a = state[i][0]
            b = state[i][1]
            state[i][0] = self._gf_mult(4, a) ^ self._gf_mult(4, b)
            state[i][1] = self._gf_mult(4, a) ^ self._gf_mult(4, b)
        return state

    def _gf_mult(self, a, b):
        p = 0
        for _ in range(4):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x8
            a <<= 1
            if hi_bit_set:
                a ^= 0x13
            b >>= 1
        return p % 0x10

    def encrypt(self, plaintext_list, key):
        '''加密函数'''
        state = [[plaintext_list[0][0], plaintext_list[0][1]], [plaintext_list[1][0], plaintext_list[1][1]]]
        round_keys = self._key_expansion(key)
        state = self._add_round_key(state, [[round_keys[0], round_keys[1]], [round_keys[2], round_keys[3]]])

        for i in range(2):
            state = self._sub_bytes(state, self.S_BOX)
            state = self._shift_rows(state)
            if i == 1:
                state = self._mix_columns(state)
            state = self._add_round_key(state, [[round_keys[4 + i * 2], round_keys[5 + i * 2]],
                                                [round_keys[6 + i * 2], round_keys[7 + i * 2]]])

        return state

    def _inv_shift_rows(self, state):
        # 逆向行移位
        for i in range(2):
            state[i] = state[i][-i:] + state[i][:-i]
        return state

    def _inv_sub_bytes(self, state, inv_s_box):
        # 逆向字节替代
        for i in range(2):
            for j in range(2):
                state[i][j] = self._sub_nibbles(state[i][j], inv_s_box)
        return state

    def _inv_mix_columns(self, state):
        # 逆向混淆
        for i in range(2):
            a = state[i][0]
            b = state[i][1]
            state[i][0] = self._gf_mult(9, a) ^ self._gf_mult(2, b)
            state[i][1] = self._gf_mult(2, a) ^ self._gf_mult(9, b)
        return state

    def decrypt(self, ciphertext_list, key):
        # 将密文转为状态矩阵
        state = [[ciphertext_list[0][0], ciphertext_list[0][1]],
                 [ciphertext_list[1][0], ciphertext_list[1][1]]]
        round_keys = self._key_expansion(key)

        # 逆向操作：轮密钥加
        state = self._add_round_key(state, [[round_keys[4], round_keys[5]],
                                            [round_keys[6], round_keys[7]]])

        for i in range(2):
            # 逆向操作：行移位
            state = self._inv_shift_rows(state)
            # 逆向操作：字节替代
            state = self._inv_sub_bytes(state, self.INV_S_BOX)
            # 逆向操作：轮密钥加
            state = self._add_round_key(state, [[round_keys[2 - i * 2], round_keys[3 - i * 2]],
                                                [round_keys[0 - i * 2], round_keys[1 - i * 2]]])

        # 逆向操作：混淆
        state = self._inv_mix_columns(state)

        # 逆向操作：轮密钥加
        state = self._add_round_key(state, [[round_keys[0], round_keys[1]],
                                            [round_keys[2], round_keys[3]]])

        # 输出解密结果
        decrypted_text = [[state[0][0], state[0][1]],
                          [state[1][0], state[1][1]]]

        return decrypted_text

    def encrypt_ascii(self, plaintext, key):
        """加密长度为四个字符的ASCII编码的明文并返回ASCII编码的密文"""
        if len(plaintext) != 4 or not all(ord(char) < 128 for char in plaintext):
            raise ValueError("输入必须是长度为四个字符的ASCII编码")

        # 将输入的四个字符分成两个字节
        byte1 = ord(plaintext[0]) << 8 | ord(plaintext[1])
        byte2 = ord(plaintext[2]) << 8 | ord(plaintext[3])

        plaintext_bytes = [(byte1 >> 8, byte1 & 0xFF), (byte2 >> 8, byte2 & 0xFF)]
        encrypted_bytes = self.encrypt(plaintext_bytes, key)

        # 将加密后的字节转换为ASCII编码的字符串
        encrypted_text = chr(encrypted_bytes[0][0]) + chr(encrypted_bytes[0][1]) + \
                         chr(encrypted_bytes[1][0]) + chr(encrypted_bytes[1][1])
        return encrypted_text

    def decrypt_ascii(self, ciphertext, key):
        """解密长度为四个字符的ASCII编码的密文"""
        if len(ciphertext) != 4:
            raise ValueError("输入的ASCII编码密文必须是四个字符")

        # 将输入的四个字符分成两个字节
        byte1 = ord(ciphertext[0]) << 8 | ord(ciphertext[1])
        byte2 = ord(ciphertext[2]) << 8 | ord(ciphertext[3])

        ciphertext_bytes = [(byte1 >> 8, byte1 & 0xFF), (byte2 >> 8, byte2 & 0xFF)]
        decrypted_bytes = self.decrypt(ciphertext_bytes, key)

        # 将解密后的字节转换为ASCII编码的字符串
        decrypted_text = chr(decrypted_bytes[0][0]) + chr(decrypted_bytes[0][1]) + \
                         chr(decrypted_bytes[1][0]) + chr(decrypted_bytes[1][1])
        return decrypted_text

    # 用法示例

#
saes = SAES()
plaintext = "ABCD"
key = 1010101010101010
encrypted_text = saes.encrypt_ascii(plaintext, key)
print("加密后的密文:", encrypted_text)
# decrypted_text = saes.decrypt_ascii(encrypted_text, key)
# print("解密后的明文:", decrypted_text)

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

        # 加密按钮-ascii
        self.encrypt_ascii_button = QPushButton('加密(ascii)')
        self.encrypt_ascii_button.clicked.connect(self.encrypt_acsii)
        layout.addWidget(self.encrypt_ascii_button)

        # 解密按钮-ascii
        self.decrypt_ascii_button = QPushButton('解密(ASCII)')
        self.decrypt_ascii_button.clicked.connect(self.decrypt_acsii)
        layout.addWidget(self.decrypt_ascii_button)


        # 结果显示
        self.result_label = QLabel('')
        layout.addWidget(self.result_label)
        self.setLayout(layout)



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



    def encrypt_acsii(self):
        plaintext = self.plain_text_input.text()
        key = self.key_input.text()

        if plaintext == '' or key == '':
            QMessageBox.warning(self, '警告', '请输入明文和密钥')
            return

        try:
            len(plaintext) != 4 or not all(ord(char) < 128 for char in plaintext)
            key = int(key, 2)
        except ValueError:
            QMessageBox.warning(self, '警告', '输入必须是长度为四个字符的ASCII编码')
            return

        ciphertext = self.aes.encrypt_ascii(plaintext, key)
        self.cipher_text_input.setText(ciphertext)
        self.result_label.setText(f'加密成功 密文：{ciphertext}')

    def decrypt_acsii(self):
        ciphertext = self.cipher_text_input.text()
        key = self.key_input.text()

        if ciphertext == '' or key == '':
            QMessageBox.warning(self, '警告', '请输入密文和密钥')
            return

        try:
            len(ciphertext) != 4
            key = int(key, 2)
        except ValueError:
            QMessageBox.warning(self, '警告', '输入必须是长度为四个字符的ASCII编码')
            return

        plaintext = self.aes.decrypt_ascii(ciphertext, key)

        plaintext_str = ''.join([f'{plaintext[i][j]:04b}' for i in range(2) for j in range(2)])

        plaintext_binary = plaintext_str[0:4] + plaintext_str[8:12] + plaintext_str[4:8] + plaintext_str[12:16]
        self.plain_text_input.setText(plaintext_binary)
        self.result_label.setText(f'解密成功 明文：{plaintext_binary}')




def main():
    app = QApplication(sys.argv)
    window = SAESApp()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
