"""
AES-128 (Rijndael) — учебная реализация
Блок: 128 бит (16 байт), ключ: 128 бит (16 байт), раундов: 10
"""

# ------------------------------------------------------------
# 1. S-бокс (SubBytes)
# ------------------------------------------------------------
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_S_BOX = [0] * 256
for i, val in enumerate(S_BOX):
    INV_S_BOX[val] = i

# ------------------------------------------------------------
# 2. Умножение в поле GF(2 ^ 8) для MixColumns
# ------------------------------------------------------------
def galois_mult(a, b):
    """Умножение в GF(2 ^ 8) с неприводимым многочленом x ^ 8 + x ^ 4 + x ^ 3 + x + 1"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a <<= 1
        if hi_bit:
            a ^= 0x1B
        b >>= 1
    return p & 0xFF

# ------------------------------------------------------------
# 3. Основные преобразования AES
# ------------------------------------------------------------
def sub_bytes(state, inv=False):
    box = INV_S_BOX if inv else S_BOX
    for i in range(16):
        state[i] = box[state[i]]

def shift_rows(state, inv = False):
    # state представлен как список из 16 байт (матрица 4x4 по колонкам)
    for r in range(1, 4):
        row = [state[r + 4 * c] for c in range(4)]
        shift = -r if inv else r
        row = row[shift:] + row[:shift]
        for c in range(4):
            state[r + 4 * c] = row[c]

def mix_columns(state, inv = False):
    for col in range(4):
        s0 = state[0 * 4 + col]
        s1 = state[1 * 4 + col]
        s2 = state[2 * 4 + col]
        s3 = state[3 * 4 + col]
        if not inv:
            state[0 * 4 + col] = galois_mult(s0, 2) ^ galois_mult(s1, 3) ^ s2 ^ s3
            state[1 * 4 + col] = s0 ^ galois_mult(s1, 2) ^ galois_mult(s2, 3) ^ s3
            state[2 * 4 + col] = s0 ^ s1 ^ galois_mult(s2, 2) ^ galois_mult(s3, 3)
            state[3 * 4 + col] = galois_mult(s0, 3) ^ s1 ^ s2 ^ galois_mult(s3, 2)
        else:
            state[0 * 4 + col] = (galois_mult(s0, 0x0E) ^ galois_mult(s1, 0x0B) ^ galois_mult(s2, 0x0D) ^ galois_mult(s3, 0x09))
            state[1 * 4 + col] = (galois_mult(s0, 0x09) ^ galois_mult(s1, 0x0E) ^ galois_mult(s2, 0x0B) ^ galois_mult(s3, 0x0D))
            state[2 * 4 + col] = (galois_mult(s0, 0x0D) ^ galois_mult(s1, 0x09) ^ galois_mult(s2, 0x0E) ^ galois_mult(s3, 0x0B))
            state[3 * 4 + col] = (galois_mult(s0, 0x0B) ^ galois_mult(s1, 0x0D) ^ galois_mult(s2, 0x09) ^ galois_mult(s3, 0x0E))

def add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]

# ------------------------------------------------------------
# 4. Развертка ключа (Key Schedule) для AES-128
# ------------------------------------------------------------
Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

def key_expansion(key):
    """key: список из 16 байт; возвращает список из 11 раундовых ключей (каждый по 16 байт)"""
    # Преобразуем ключ в 4 слова по 4 байта
    words = []
    for i in range(4):
        word = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]
        words.append(word)
    
    # Генерируем еще 40 слов (всего нужно 44 слова для 11 раундов)
    for i in range(4, 44):
        temp = words[i-1][:]  # копия предыдущего слова
        if i % 4 == 0:
            # циклический сдвиг влево на 1 байт
            temp = temp[1:] + temp[:1]
            # SubBytes
            temp = [S_BOX[b] for b in temp]
            # XOR с Rcon
            temp[0] ^= Rcon[i // 4 - 1]
        # XOR с i-4 словом
        new_word = [words[i - 4][j] ^ temp[j] for j in range(4)]
        words.append(new_word)
    
    # Преобразуем слова в раундовые ключи (каждый по 16 байт)
    round_keys = []
    for i in range(0, 44, 4):
        round_key = []
        for j in range(4):
            round_key.extend(words[i + j])
        round_keys.append(round_key)
    
    return round_keys

# ------------------------------------------------------------
# 5. Шифрование и дешифрование одного блока
# ------------------------------------------------------------
def aes_encrypt_block(plaintext, key):
    """
    plaintext, key: bytes или list из 16 байт
    возвращает: list из 16 байт (шифротекст)
    """
    if isinstance(plaintext, bytes):
        state = list(plaintext)
    else:
        state = plaintext[:]
    if isinstance(key, bytes):
        key_bytes = list(key)
    else:
        key_bytes = key[:]
    
    round_keys = key_expansion(key_bytes)
    
    # начальный раунд
    add_round_key(state, round_keys[0])
    
    # 9 полных раундов
    for r in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[r])
    
    # финальный раунд (без MixColumns)
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])
    
    return state

def aes_decrypt_block(ciphertext, key):
    """
    ciphertext, key: bytes или list из 16 байт
    возвращает: list из 16 байт (расшифрованный текст)
    """
    if isinstance(ciphertext, bytes):
        state = list(ciphertext)
    else:
        state = ciphertext[:]
    if isinstance(key, bytes):
        key_bytes = list(key)
    else:
        key_bytes = key[:]
    
    round_keys = key_expansion(key_bytes)
    
    # начальный раунд дешифрования
    add_round_key(state, round_keys[10])
    
    # 9 полных раундов (обратный порядок)
    for r in range(9, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[r])
        inv_mix_columns(state)
    
    # финальный раунд (без InvMixColumns)
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])
    
    return state

# вспомогательные функции для дешифрования
def inv_shift_rows(state):
    shift_rows(state, inv = True)

def inv_sub_bytes(state):
    sub_bytes(state, inv = True)

def inv_mix_columns(state):
    mix_columns(state, inv = True)

# ------------------------------------------------------------
# 6. Вспомогательные функции для работы с текстом
# ------------------------------------------------------------
def pad_data(data):
    """Дополнение данных до размера, кратного 16 байтам (PKCS7)"""
    padding_len = 16 - (len(data) % 16)
    return data + bytes([padding_len] * padding_len)

def unpad_data(data):
    """Удаление дополнения PKCS7"""
    padding_len = data[-1]
    return data[:-padding_len]

def encrypt_text(plaintext, key):
    """Шифрование текста произвольной длины"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    padded_data = pad_data(plaintext)
    ciphertext = b''
    
    for i in range(0, len(padded_data), 16):
        block = padded_data[i:i + 16]
        encrypted_block = aes_encrypt_block(block, key)
        ciphertext += bytes(encrypted_block)
    
    return ciphertext

def decrypt_text(ciphertext, key):
    """Дешифрование текста произвольной длины"""
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    
    plaintext_padded = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        decrypted_block = aes_decrypt_block(block, key)
        plaintext_padded += bytes(decrypted_block)
    
    return unpad_data(plaintext_padded).decode('utf-8')

# ------------------------------------------------------------
# 7. Пример использования и тест
# ------------------------------------------------------------
def print_state(name, data):
    if isinstance(data, bytes):
        hex_str = data.hex().upper()
    else:
        hex_str = bytes(data).hex().upper()
    print(f"{name}: {hex_str}")

if __name__ == "__main__":
    print("=== AES-128 (Rijndael) ===")
    print("Размер блока: 128 бит (16 байт)")
    print("Длина ключа:  128 бит (16 байт)")
    print("Число раундов: 10 (согласно формуле max(4,4)+6)")
    print()
    
    # Стандартный тестовый вектор AES
    key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    
    plaintext = bytes([0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34])
    
    print("Тест 1: Шифрование одного блока")
    print_state("Исходный текст     ", plaintext)
    print_state("Ключ               ", key)
    
    encrypted = aes_encrypt_block(plaintext, key)
    decrypted = aes_decrypt_block(encrypted, key)
    
    print_state("Зашифрованный текст", encrypted)
    print_state("Расшифрованный текст", decrypted)
    
    if bytes(decrypted) == plaintext:
        print("\n✅ Успех! Блочное шифрование/дешифрование работает корректно.")
    else:
        print("\n❌ Ошибка: расшифровка неверна.")
    
    print("\n" + "="*50)
    print("Тест 2: Шифрование текста произвольной длины")
    
    key_128 = b'MySecretKey12345'  # 16 байт
    message = "Привет, мир! Это тестовое сообщение для AES-128."
    
    print(f"Исходное сообщение: {message}")
    print(f"Ключ: {key_128.decode('ascii')}")
    
    encrypted_msg = encrypt_text(message, key_128)
    print(f"Зашифровано (hex): {encrypted_msg.hex()}")
    
    decrypted_msg = decrypt_text(encrypted_msg, key_128)
    print(f"Расшифрованное сообщение: {decrypted_msg}")
    
    if decrypted_msg == message:
        print("✅ Успех! Текст успешно зашифрован и расшифрован.")
    else:
        print("❌ Ошибка при работе с текстом.")
    
    print("\n" + "="*50)
    print("Тест 3: Сравнение с официальным тестовым вектором AES")
    # Ожидаемый результат для данного ключа и plaintext
    expected_cipher = bytes([0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32])
    
    if bytes(encrypted) == expected_cipher:
        print("✅ Соответствует официальному тестовому вектору NIST!")
    else:
        print(f"Получено:     {bytes(encrypted).hex().upper()}")
        print(f"Ожидалось:    {expected_cipher.hex().upper()}")