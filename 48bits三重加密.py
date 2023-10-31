import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox

class SAESTriple:
    def __init__(self):
        self.S_BOX = [
            [0x9, 0x4, 0xA, 0xB],
            [0xD, 0x1, 0x8, 0x5],
            [0x6, 0x2, 0x0, 0x3],
            [0xC, 0xE, 0xF, 0x7]
        ]

        self.INV_S_BOX = [
            [0xE, 0xB, 0xD, 0x9],
            [0x9, 0xE, 0xB, 0xD],
            [0xD, 0x9, 0xE, 0xB],
            [0xB, 0xD, 0x9, 0xE]
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
                state[i][j] ^= round_key[i][j]  # 修复此处
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

    # ... （其余的 SAES 类代码不变）

    def encrypt(self, plaintext_list, keys):
        key1, key2, key3 = keys
        # 轮密钥加操作
        state = self._add_round_key(plaintext_list, key1)

        for i in range(2):
            state = self._sub_bytes(state, self.S_BOX)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, key2)
            state = self._sub_bytes(state, self.S_BOX)
            state = self._shift_rows(state)
            state = self._add_round_key(state, key3)

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

    def decrypt(self, ciphertext_list, keys):
        key1, key2, key3 = keys
        state = self._add_round_key(ciphertext_list, key3)

        for i in range(2):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state, self.INV_S_BOX)  # 使用 INV_S_BOX
            state = self._add_round_key(state, key2)
            state = self._inv_mix_columns(state)
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state, self.INV_S_BOX)  # 使用 INV_S_BOX
            state = self._add_round_key(state, key1)

        return state


class SAESAppTriple(QWidget):
    def __init__(self):
        super().__init__()
        self.aes = SAESTriple()
        self.initUI()

    # ... （其余的 SAESApp 类代码不变）
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
        self.key_label = QLabel('密钥(48位二进制):')
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

    def encrypt(self):
      plaintext = self.plain_text_input.text()
      keys = self.key_input.text()

      if plaintext == '' or keys == '':
        QMessageBox.warning(self, '警告', '请输入明文和三个密钥')
        return

      try:
        plaintext = [[int(plaintext[0:4], 2), int(plaintext[8:12], 2)],
                     [int(plaintext[4:8], 2), int(plaintext[12:16], 2)]
                    ]
        key1 = int(keys[0:16], 2)
        key2 = int(keys[16:32], 2)
        key3 = int(keys[32:48], 2)
      except ValueError:
        QMessageBox.warning(self, '警告', '请输入正确的二进制数字')
        return

      keys = [key1, key2, key3]

      key1 = [[(key1 >> 4) & 0xF, key1 & 0xF], [(key1 >> 12) & 0xF, (key1 >> 8) & 0xF]]
      key2 = [[(key2 >> 4) & 0xF, key2 & 0xF], [(key2 >> 12) & 0xF, (key2 >> 8) & 0xF]]
      key3 = [[(key3 >> 4) & 0xF, key3 & 0xF], [(key3 >> 12) & 0xF, (key3 >> 8) & 0xF]]
  
      ciphertext = self.aes.encrypt(plaintext, [key1, key2, key3])
      ciphertext_str = ''.join([f'{ciphertext[i][j]:04b}' for i in range(2) for j in range(2)])

      ciphertext_binary = ciphertext_str[0:4] + ciphertext_str[8:12] + ciphertext_str[4:8] + ciphertext_str[12:16]
      self.cipher_text_input.setText(ciphertext_binary)
      self.result_label.setText(f'加密成功 密文：{ciphertext_binary}')

    def decrypt(self):
      ciphertext = self.cipher_text_input.text()
      keys = self.key_input.text()

      if ciphertext == '' or keys == '':
        QMessageBox.warning(self, '警告', '请输入密文和三个密钥')
        return

      try:
        ciphertext = [[int(ciphertext[0:4], 2), int(ciphertext[8:12], 2)],
                     [int(ciphertext[4:8], 2), int(ciphertext[12:16], 2)]
                    ]
        key1 = int(keys[0:16], 2)
        key2 = int(keys[16:32], 2)
        key3 = int(keys[32:48], 2)
      except ValueError:
        QMessageBox.warning(self, '警告', '请输入正确的二进制数字')
        return

      keys = [key1, key2, key3]

      key1 = [[(key1 >> 4) & 0xF, key1 & 0xF], [(key1 >> 12) & 0xF, (key1 >> 8) & 0xF]]
      key2 = [[(key2 >> 4) & 0xF, key2 & 0xF], [(key2 >> 12) & 0xF, (key2 >> 8) & 0xF]]
      key3 = [[(key3 >> 4) & 0xF, key3 & 0xF], [(key3 >> 12) & 0xF, (key3 >> 8) & 0xF]]

      plaintext = self.aes.decrypt(ciphertext, [key1, key2, key3])

      plaintext_str = ''.join([f'{plaintext[i][j]:04b}' for i in range(2) for j in range(2)])

      plaintext_binary = plaintext_str[0:4] + plaintext_str[8:12] + plaintext_str[4:8] + plaintext_str[12:16]
      self.plain_text_input.setText(plaintext_binary)
      self.result_label.setText(f'解密成功 明文：{plaintext_binary}')



def main():
    app = QApplication(sys.argv)
    window = SAESAppTriple()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

