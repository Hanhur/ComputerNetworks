# Для реального шифрования используйте AES из библиотеки cryptography:
# Примечание: Это учебная реализация. Для реального шифрования используйте библиотеку cryptography или pycryptodome.
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

"""
Учебная реализация алгоритма DES (Data Encryption Standard)
и Triple DES (3DES) на основе описания из текста.

Данная реализация НЕ безопасна для реального использования,
но наглядно показывает:
- начальную и конечную перестановки битов
- сеть Фейстеля (16 раундов)
- S-блоки (подстановки)
- генерацию раундовых ключей из 56-битного ключа
- режим ECB (для простоты)
"""

# ============================================================
# 1. Таблицы перестановок и S-блоки (стандарт DES)
# ============================================================

# Начальная перестановка IP (Initial Permutation)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Конечная перестановка IP^-1 (Inverse Initial Permutation)
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Расширение 32 -> 48 бит (E-box)
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S-блоки (8 штук, каждый 4x16)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Перестановка P после S-блоков (32 бита)
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# Сжатие ключа с 56 до 48 бит (PC-2)
PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Количество сдвигов для каждого раунда (1 или 2 бита)
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# ============================================================
# 2. Вспомогательные функции для работы с битами
# ============================================================

def string_to_bits(text: str) -> str:
    """Преобразует строку в битовую строку (ASCII 8 бит на символ)"""
    bits = ''
    for ch in text:
        bits += format(ord(ch), '08b')
    return bits

def bits_to_string(bits: str) -> str:
    """Преобразует битовую строку обратно в строку"""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def hex_to_bits(hex_str: str) -> str:
    """Преобразует шестнадцатеричную строку в битовую"""
    bits = ''
    for h in hex_str:
        bits += format(int(h, 16), '04b')
    return bits

def bits_to_hex(bits: str) -> str:
    """Преобразует битовую строку в шестнадцатеричную"""
    hex_str = ''
    for i in range(0, len(bits), 4):
        nibble = bits[i:i+4]
        if len(nibble) == 4:
            hex_str += format(int(nibble, 2), 'x')
    return hex_str

def permute(bits: str, table: list) -> str:
    """Выполняет перестановку битов согласно таблице"""
    return ''.join(bits[i-1] for i in table)

def left_rotate(bits: str, n: int) -> str:
    """Циклический сдвиг влево на n бит"""
    return bits[n:] + bits[:n]

def xor(a: str, b: str) -> str:
    """Побитовое XOR двух битовых строк одинаковой длины"""
    return ''.join('1' if x != y else '0' for x, y in zip(a, b))

# ============================================================
# 3. Функция раунда DES (Фейстель)
# ============================================================

def des_round(right: str, round_key: str) -> str:
    """
    Функция раунда DES:
    1. Расширение правой половины (32 -> 48)
    2. XOR с раундовым ключом
    3. Подстановка через S-блоки (48 -> 32)
    4. Перестановка P
    """
    # Расширение E
    expanded = permute(right, E)  # 48 бит
    
    # XOR с ключом
    xored = xor(expanded, round_key)  # 48 бит
    
    # S-блоки: разбиваем на 8 кусков по 6 бит, каждый превращаем в 4 бита
    s_box_output = ''
    for i in range(8):
        chunk = xored[i * 6:(i + 1) * 6]
        row = int(chunk[0] + chunk[5], 2)  # 1-й и 6-й биты -> строка
        col = int(chunk[1:5], 2)            # 2-5 биты -> столбец
        val = S_BOXES[i][row][col]
        s_box_output += format(val, '04b')
    
    # Перестановка P
    result = permute(s_box_output, P)  # 32 бита
    return result

# ============================================================
# 4. Генерация раундовых ключей из 64-битного ключа (с учётом четности)
# ============================================================

def generate_round_keys(key_64bits: str) -> list:
    """
    Из 64-битного ключа (с битами чётности) генерирует 16 раундовых ключей по 48 бит.
    Если передан 56-битный ключ, он дополняется нулями до 64 бит для совместимости.
    """
    if len(key_64bits) == 56:
        # Для упрощения: дополняем нулями до 64 бит (в реальном DES ключ 64 бита, но 8 бит чётности)
        key_64bits = key_64bits + '00000000'
    elif len(key_64bits) != 64:
        raise ValueError(f"Ключ должен быть 56 или 64 бита, получено {len(key_64bits)}")
    
    # Удаляем биты чётности (каждый 8-й бит) -> 56 бит
    key_56bits = ''
    for i in range(64):
        if (i + 1) % 8 != 0:
            key_56bits += key_64bits[i]
    
    # Разбиваем на левую и правую половины по 28 бит
    left = key_56bits[:28]
    right = key_56bits[28:]
    
    round_keys = []
    for round_num in range(16):
        # Сдвигаем обе половины
        left = left_rotate(left, SHIFTS[round_num])
        right = left_rotate(right, SHIFTS[round_num])
        
        # Объединяем и сжимаем с помощью PC2
        combined = left + right  # 56 бит
        round_key = permute(combined, PC2)  # 48 бит
        round_keys.append(round_key)
    
    return round_keys

# ============================================================
# 5. Основная функция DES (один блок 64 бита)
# ============================================================

def des_encrypt_block(plain_block_64: str, round_keys: list) -> str:
    """
    Шифрует один 64-битный блок с помощью DES (сеть Фейстеля, 16 раундов)
    """
    if len(plain_block_64) != 64:
        raise ValueError(f"Блок должен быть 64 бита, получено {len(plain_block_64)}")
    
    # Начальная перестановка
    block = permute(plain_block_64, IP)  # 64 бита
    left = block[:32]
    right = block[32:]
    
    # 16 раундов
    for i in range(16):
        new_left = right
        f_result = des_round(right, round_keys[i])
        new_right = xor(left, f_result)
        left, right = new_left, new_right
    
    # Финальная перестановка (меняем местами left и right перед IP^-1)
    final_block = permute(right + left, IP_INV)
    return final_block

def des_decrypt_block(cipher_block_64: str, round_keys: list) -> str:
    """
    Дешифрует один 64-битный блок. Ключи подаются в обратном порядке.
    """
    return des_encrypt_block(cipher_block_64, round_keys[::-1])

# ============================================================
# 6. Режим ECB для сообщений произвольной длины (с дополнением PKCS7)
# ============================================================

def pad_pkcs7(data_bits: str, block_size_bits = 64) -> str:
    """Дополняет битовую строку до кратности block_size_bits (PKCS7)"""
    block_size_bytes = block_size_bits // 8
    data_bytes = len(data_bits) // 8
    padding_bytes = block_size_bytes - (data_bytes % block_size_bytes)
    if padding_bytes == 0:
        padding_bytes = block_size_bytes
    padding_bits = format(padding_bytes, '08b') * padding_bytes
    return data_bits + padding_bits

def unpad_pkcs7(data_bits: str) -> str:
    """Удаляет дополнение PKCS7"""
    padding_bytes = int(data_bits[-8:], 2)
    if padding_bytes > 8:
        return data_bits
    return data_bits[:-padding_bytes * 8]

def des_encrypt_ecb(plaintext: str, key_64bits: str) -> str:
    """Шифрует строку произвольной длины в режиме ECB"""
    round_keys = generate_round_keys(key_64bits)
    plain_bits = string_to_bits(plaintext)
    plain_bits = pad_pkcs7(plain_bits, 64)
    
    cipher_bits = ''
    for i in range(0, len(plain_bits), 64):
        block = plain_bits[i:i + 64]
        cipher_bits += des_encrypt_block(block, round_keys)
    return cipher_bits

def des_decrypt_ecb(cipher_bits: str, key_64bits: str) -> str:
    """Дешифрует битовую строку в режиме ECB"""
    round_keys = generate_round_keys(key_64bits)
    plain_bits = ''
    for i in range(0, len(cipher_bits), 64):
        block = cipher_bits[i:i + 64]
        plain_bits += des_decrypt_block(block, round_keys)
    plain_bits = unpad_pkcs7(plain_bits)
    return bits_to_string(plain_bits)

# ============================================================
# 7. Triple DES (3DES) – шифрование с двумя ключами
# ============================================================

def triple_des_encrypt(plaintext: str, key1_64bits: str, key2_64bits: str) -> str:
    """
    Triple DES (3DES) по схеме E-D-E с двумя ключами:
    Шифрование ключом K1 -> Дешифрование ключом K2 -> Шифрование ключом K1
    Совместим с одинарным DES, если key1 == key2.
    """
    # Первое шифрование (K1)
    round_keys1 = generate_round_keys(key1_64bits)
    plain_bits = string_to_bits(plaintext)
    plain_bits = pad_pkcs7(plain_bits, 64)
    
    # ECB режим для простоты
    intermediate1_bits = ''
    for i in range(0, len(plain_bits), 64):
        block = plain_bits[i:i + 64]
        intermediate1_bits += des_encrypt_block(block, round_keys1)
    
    # Дешифрование (K2)
    round_keys2 = generate_round_keys(key2_64bits)
    intermediate2_bits = ''
    for i in range(0, len(intermediate1_bits), 64):
        block = intermediate1_bits[i:i + 64]
        intermediate2_bits += des_decrypt_block(block, round_keys2)
    
    # Второе шифрование (K1)
    final_cipher_bits = ''
    for i in range(0, len(intermediate2_bits), 64):
        block = intermediate2_bits[i:i + 64]
        final_cipher_bits += des_encrypt_block(block, round_keys1)
    
    return final_cipher_bits

def triple_des_decrypt(cipher_bits: str, key1_64bits: str, key2_64bits: str) -> str:
    """
    Дешифрование Triple DES (обратный порядок):
    Дешифрование K1 -> Шифрование K2 -> Дешифрование K1
    """
    round_keys1 = generate_round_keys(key1_64bits)
    round_keys2 = generate_round_keys(key2_64bits)
    
    # Первое дешифрование (K1)
    intermediate1_bits = ''
    for i in range(0, len(cipher_bits), 64):
        block = cipher_bits[i:i + 64]
        intermediate1_bits += des_decrypt_block(block, round_keys1)
    
    # Шифрование (K2)
    intermediate2_bits = ''
    for i in range(0, len(intermediate1_bits), 64):
        block = intermediate1_bits[i:i + 64]
        intermediate2_bits += des_encrypt_block(block, round_keys2)
    
    # Второе дешифрование (K1)
    final_bits = ''
    for i in range(0, len(intermediate2_bits), 64):
        block = intermediate2_bits[i:i + 64]
        final_bits += des_decrypt_block(block, round_keys1)
    
    final_bits = unpad_pkcs7(final_bits)
    return bits_to_string(final_bits)

# ============================================================
# 8. Пример использования
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Учебная реализация DES и Triple DES")
    print("=" * 60)
    
    # Пример 1: Одинарный DES (56-битный ключ, но передаём 64 бита)
    print("\n1. Одинарный DES (56-битный ключ):")
    key_56 = "133457799BBCDFF1"  # 16 hex = 64 бита (включая биты чётности)
    # Из текста: ключ 56 бит, но в реализации используем 64 бита (стандарт DES)
    plaintext = "HELLO DES"
    
    print(f"Исходный текст: {plaintext}")
    cipher_bits = des_encrypt_ecb(plaintext, hex_to_bits(key_56))
    print(f"Зашифровано (hex): {bits_to_hex(cipher_bits)}")
    
    decrypted = des_decrypt_ecb(cipher_bits, hex_to_bits(key_56))
    print(f"Расшифровано: {decrypted}")
    
    # Пример 2: Triple DES с двумя ключами (112 бит эффективной длины)
    print("\n2. Triple DES (два 56-битных ключа, схема E-D-E):")
    key1_hex = "133457799BBCDFF1"  # 64 бита
    key2_hex = "A1B2C3D4E5F67890"  # другой ключ
    plaintext2 = "Secret message for 3DES"
    
    print(f"Исходный текст: {plaintext2}")
    cipher_3des = triple_des_encrypt(plaintext2, hex_to_bits(key1_hex), hex_to_bits(key2_hex))
    print(f"Зашифровано (hex): {bits_to_hex(cipher_3des)[:64]}... (обрезано)")
    
    decrypted2 = triple_des_decrypt(cipher_3des, hex_to_bits(key1_hex), hex_to_bits(key2_hex))
    print(f"Расшифровано: {decrypted2}")
    
    # Пример 3: Совместимость с одинарным DES (key1 == key2)
    print("\n3. Совместимость Triple DES с одинарным DES (key1 == key2):")
    same_key = hex_to_bits(key1_hex)
    plaintext3 = "Test compatibility"
    
    des_cipher = des_encrypt_ecb(plaintext3, same_key)
    tdes_cipher = triple_des_encrypt(plaintext3, same_key, same_key)
    
    print(f"DES   шифротекст (hex): {bits_to_hex(des_cipher)}")
    print(f"3DES  шифротекст (hex): {bits_to_hex(tdes_cipher)}")
    print(f"Результаты одинаковы: {des_cipher == tdes_cipher}")
    
    print("\n" + "=" * 60)
    print("Примечание: Это учебная реализация. Для реального шифрования используйте библиотеку cryptography или pycryptodome.")
    print("=" * 60)