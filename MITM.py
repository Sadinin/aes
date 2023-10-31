import random

from SAES_PRO import SAES_PRO
class MiddleMeetAttack:
    def __init__(self):
        self.saes = SAES_PRO()

    @staticmethod
    def binary_string_to_list(binary_string):
        # 将二进制字符串转换为二维列表
        binary_list = [[int(bit) for bit in binary_string[:8]], [int(bit) for bit in binary_string[8:]]]
        return binary_list

    def generate_middle_value(self, plaintext_list, key1, key2):
        # 加密明文并返回中间值
        encrypted_text = self.saes.encrypt(plaintext_list, key1)
        middle_value = self.saes.encrypt(encrypted_text, key2)
        return middle_value

    def perform_middle_meet_attack(self, known_plaintext, known_ciphertext, num_trials=1000000):
        # 已知的明文和密文对
        plaintext_list = self.binary_string_to_list(known_plaintext)
        ciphertext_list = self.binary_string_to_list(known_ciphertext)

        # 循环尝试不同的密钥组合
        for attempt in range(1, num_trials + 1):
            key1 = random.randint(0, 255)  # 随机生成8位密钥
            key2 = random.randint(0, 255)  # 随机生成8位密钥

            # 计算中间值
            middle_value = self.generate_middle_value(plaintext_list, key1, key2)

            # 如果中间值与已知的中间值相等，则找到了正确的密钥组合
            if middle_value == ciphertext_list:
                return key1, key2, attempt

        # 如果在指定次数内未找到正确的密钥组合，则返回None和攻击次数
        return None, None, num_trials

# 示例使用
known_plaintext = '1010101010101010'  # 已知的明文
known_ciphertext = '1100000000000000'  # 对应的已知密文

# 创建中间相遇攻击对象
attack = MiddleMeetAttack()

# 人为控制攻击次数
num_trials = 1000000

# 尝试进行中间相遇攻击
key1, key2, attempts = attack.perform_middle_meet_attack(known_plaintext, known_ciphertext, num_trials)

# 输出结果
if key1 is not None and key2 is not None:
    print("Found correct keys: K1 =", key1, ", K2 =", key2)
    print("Number of attempts:", attempts)
else:
    print("Failed to find correct keys after", attempts, "attempts.")

