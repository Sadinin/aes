from SAES import SAES
import random


class SAES_PRO(SAES):
    def double_encrypt(self, plaintext, key):
        # 从32位密钥中拆分为两个16位密钥
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 使用第一个密钥加密
        intermediate_ciphertext = super().encrypt(plaintext, key1)
        # 使用第二个密钥再次加密
        final_ciphertext = super().encrypt(intermediate_ciphertext, key2)

        return final_ciphertext

    def double_decrypt(self, ciphertext, key):
        # 从32位密钥中拆分为两个16位密钥
        key1 = (key >> 16) & 0xFFFF
        key2 = key & 0xFFFF

        # 使用第二个密钥解密
        intermediate_plaintext = super().decrypt(ciphertext, key2)
        # 使用第一个密钥再次解密
        final_plaintext = super().decrypt(intermediate_plaintext, key1)

        return final_plaintext

    def matrix_to_int(self, matrix):
        # Flatten the matrix
        flattened = [matrix[0][0], matrix[1][0], matrix[0][1], matrix[1][1]]

        # Convert each number to 4-bit binary representation
        bin_values = [format(val, '04b') for val in flattened]

        # Join all binary values to form a 16-bit binary string
        bin_string = ''.join(bin_values)

        # Convert the 16-bit binary string to an integer
        return int(bin_string, 2)

    def meet_in_the_middle_attack(self, plaintext, ciphertext):
        # 初始化一个空字典，用于存储中间值与密钥的映射
        intermediate_values = {}
        res = []
        # 枚举所有可能的16位密钥
        for key1 in range(0x10000):
            # 使用第一个密钥加密明文
            intermediate_value = self.matrix_to_int(self.encrypt(plaintext, key1))

            # 将中间值与第一个密钥映射存储在字典中
            intermediate_values[intermediate_value] = key1

        # 枚举所有可能的16位密钥
        for key2 in range(0x10000):
            # 使用第二个密钥解密密文
            intermediate_value = self.matrix_to_int(self.decrypt(ciphertext, key2))

            # 检查中间值是否在字典中
            if intermediate_value in intermediate_values:
                # 如果找到匹配的中间值，表示成功找到了密钥
                key1 = intermediate_values[intermediate_value]
                key2 = key2
                # 合并密钥并以16进制表示
                combined_key = "{:04X}".format((key1 << 16) | key2)
                res.append(combined_key)

        # 如果没有找到匹配的密钥，则返回None表示失败
        return res

    def triple_encrypt(self, plaintext, key1, key2, key3):
        # 使用第一个密钥K1进行加密
        ciphertext1 = self.encrypt(plaintext, key1)
        # 使用第二个密钥K2进行加密
        ciphertext2 = self.encrypt(ciphertext1, key2)
        # 使用第三个密钥K3进行加密
        ciphertext3 = self.encrypt(ciphertext2, key3)
        # 返回最终的密文
        return ciphertext3

    def triple_decrypt(self, ciphertext, key1, key2, key3):
        # 使用第三个密钥K3进行解密
        intermediate_plaintext2 = self.decrypt(ciphertext, key3)
        # 使用第二个密钥K2进行解密
        intermediate_plaintext1 = self.decrypt(intermediate_plaintext2, key2)
        # 使用第一个密钥K1进行解密
        plaintext = self.decrypt(intermediate_plaintext1, key1)
        # 返回最终的明文
        return plaintext

    def generate_random_iv(self):
        # 生成一个随机的16位初始向量（IV）
        return random.randint(0, 0xFFFF)

    def split_into_16_bit_groups(self, number):
        # 初始化一个空列表，用于存储分组结果
        groups = []
        res = []
        # 使用位运算将32位整数分成16位一组，并依次添加到列表中
        for _ in range(2):
            group = number & 0xFFFF  # 获取低16位
            groups.append(group)
            number >>= 16  # 将整数右移16位，处理下一组
        # 将groups 中的元素从末尾依次取出，添加到res中
        for i in range(len(groups)):
            res.append(groups.pop())
        return res

    def cbc_encrypt(self, plaintext, key, iv):
        # 初始化一个空的密文列表
        ciphertext = []
        plaintexts = self.split_into_16_bit_groups(plaintext)
        # 对每个明文分组进行加密
        for block in plaintexts:
            # 将明文分组与前一个密文分组（或IV）进行异或运算
            if not ciphertext:
                # 如果是第一个分组，使用初始向量
                prev_block = iv
            else:
                prev_block = ciphertext[-1]

            xored_block = block ^ prev_block
            xored_block_expand = bin(xored_block)[2:].zfill(16)
            #print('异或后的分组：', xored_block_expand)
            plaintext_matrix = [
                [int(xored_block_expand[0:4], 2), int(xored_block_expand[8:12], 2)],
                [int(xored_block_expand[4:8], 2), int(xored_block_expand[12:16], 2)]
            ]

            # 使用密钥加密异或后的分组
            encrypted_block = self.encrypt(plaintext_matrix, key)
            concatenated_binary = bin(encrypted_block[0][0])[2:].zfill(4) + bin(encrypted_block[1][0])[2:].zfill(
                4) + bin(encrypted_block[0][1])[2:].zfill(4) + bin(encrypted_block[1][1])[2:].zfill(4)
            #print('加密后的分组：', concatenated_binary)
            # 将加密后的分组添加到密文列表
            ciphertext.append(int(concatenated_binary, 2))

        return ciphertext

    def cbc_decrypt(self, ciphertext, key, iv):
        # 初始化一个空的明文列表
        plaintexts = []
        ciphertexts = self.split_into_16_bit_groups(ciphertext)
        #print(ciphertexts)
        # 对每个密文分组进行解密
        for block in ciphertexts:
            # 使用密钥解密密文分组
            ciphertext_block = bin(block)[2:].zfill(16)
            ciphertext_block_matrix = [
                [int(ciphertext_block[0:4], 2), int(ciphertext_block[8:12], 2)],
                [int(ciphertext_block[4:8], 2), int(ciphertext_block[12:16], 2)]
            ]
            decrypted_block_matrix = self.decrypt(ciphertext_block_matrix, key)
            #print('解密后的分组：', decrypted_block_matrix)
            # 将解密后的分组与前一个密文分组（或IV）进行异或运算
            if not plaintexts:
                # 如果是第一个分组，使用初始向量
                prev = bin(iv)[2:].zfill(16)

            else:
                prev = bin(ciphertexts[-2])[2:].zfill(16)
            prev_block = [
                [int(prev[0:4], 2), int(prev[8:12], 2)],
                [int(prev[4:8], 2), int(prev[12:16], 2)]
            ]
            xored_block_matrix = [
                [decrypted_block_matrix[0][0] ^ prev_block[0][0], decrypted_block_matrix[0][1] ^ prev_block[0][1]],
                [decrypted_block_matrix[1][0] ^ prev_block[1][0], decrypted_block_matrix[1][1] ^ prev_block[1][1]]
            ]
            #print('异或后的分组：', xored_block_matrix)
            plaintext = bin(xored_block_matrix[0][0])[2:].zfill(4) + bin(xored_block_matrix[1][0])[2:].zfill(4) + bin(
                xored_block_matrix[0][1])[2:].zfill(4) + bin(xored_block_matrix[1][1])[2:].zfill(4)
            # 将异或运算结果添加到明文列表
            plaintexts.append(plaintext)

        # 将明文列表中的分组合并成一个整体明文
        plaintexts = ''.join(plaintexts)

        return plaintexts


def trans(block):
    return bin(block[0][0])[2:].zfill(4) + bin(block[1][0])[2:].zfill(4) + bin(block[0][1])[2:].zfill(4) + bin(block[1][1])[2:].zfill(4)

