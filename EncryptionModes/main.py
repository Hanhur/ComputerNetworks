from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========

def pad(data, block_size):
    """Дополнение данных до размера, кратного block_size (PKCS7)."""
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    """Удаление дополнения PKCS7."""
    padding_len = data[-1]
    if padding_len > len(data) or padding_len == 0:
        raise ValueError("Неверное дополнение")
    return data[:-padding_len]

def xor_bytes(a, b):
    """XOR двух байтовых строк одинаковой длины."""
    return bytes(x ^ y for x, y in zip(a, b))

# ========== РЕЖИМЫ ШИФРОВАНИЯ ==========

def aes_ecb_encrypt(key, plaintext):
    """AES-ECB шифрование."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend = default_backend())
    encryptor = cipher.encryptor()
    padded = pad(plaintext, 16)
    return encryptor.update(padded) + encryptor.finalize()

def aes_ecb_decrypt(key, ciphertext):
    """AES-ECB дешифрование."""
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend = default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(decrypted_padded)

def aes_cbc_encrypt(key, plaintext, iv):
    """AES-CBC шифрование."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    padded = pad(plaintext, 16)
    return encryptor.update(padded) + encryptor.finalize()

def aes_cbc_decrypt(key, ciphertext, iv):
    """AES-CBC дешифрование."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(decrypted_padded)

def aes_cfb_encrypt(key, plaintext, iv):
    """AES-CFB (побайтовый, как в тексте, но здесь 16-байтовый сдвиг)."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()  # CFB не требует дополнения

def aes_cfb_decrypt(key, ciphertext, iv):
    """AES-CFB дешифрование."""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def aes_ctr_keystream(key, iv, length):
    """
    Генерация ключевого потока для CTR (режим потокового шифра).
    iv — начальное значение счётчика (16 байт).
    """
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend = default_backend())
    encryptor = cipher.encryptor()
    keystream = b''
    counter = int.from_bytes(iv, 'big')
    while len(keystream) < length:
        counter_bytes = counter.to_bytes(16, 'big')
        keystream += encryptor.update(counter_bytes)
        counter += 1
    return keystream[:length]

def aes_ctr_encrypt(key, plaintext, iv):
    """AES-CTR шифрование (потоковый режим)."""
    keystream = aes_ctr_keystream(key, iv, len(plaintext))
    return xor_bytes(plaintext, keystream)

def aes_ctr_decrypt(key, ciphertext, iv):
    """AES-CTR дешифрование (то же самое, что шифрование)."""
    return aes_ctr_encrypt(key, ciphertext, iv)

# ========== ДЕМОНСТРАЦИЯ АТАКИ НА ECB ==========

def demonstrate_ecb_attack():
    print("\n=== АТАКА ПЕРЕСТАНОВКОЙ БЛОКОВ НА ECB ===")
    key = os.urandom(16)
    
    # Представим данные сотрудников (16 байт имя + 8 байт должность + 8 байт премия)
    # Но для простоты: два блока по 16 байт: [имя Лесли] [премия 1000] [имя Ким] [премия 5000]
    leslie_name = b"Leslie         "  # 16 байт
    kim_name = b"Kim            "
    leslie_bonus = b"Bonus: 1000   "  # 16 байт
    kim_bonus = b"Bonus: 5000   "
    
    plaintext = leslie_name + leslie_bonus + kim_name + kim_bonus
    print("Оригинальный текст (блоки):")
    print(f"  Блок 0 (имя Лесли): {leslie_name}")
    print(f"  Блок 1 (премия Лесли): {leslie_bonus}")
    print(f"  Блок 2 (имя Ким): {kim_name}")
    print(f"  Блок 3 (премия Ким): {kim_bonus}")
    
    ciphertext = aes_ecb_encrypt(key, plaintext)
    print("\nЗашифровано в ECB. Длина ciphertext:", len(ciphertext))
    
    # Атака: заменяем блок 1 (премия Лесли) на блок 3 (премия Ким)
    ciphertext_blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    ciphertext_blocks[1] = ciphertext_blocks[3]  # перестановка
    modified_ciphertext = b''.join(ciphertext_blocks)
    
    decrypted = aes_ecb_decrypt(key, modified_ciphertext)
    print("\nПосле атаки (замена блока премии Лесли на блок премии Ким):")
    print(f"  Блок 0 (имя Лесли): {decrypted[0:16]}")
    print(f"  Блок 1 (премия Лесли): {decrypted[16:32]}")   # теперь 5000
    print(f"  Блок 2 (имя Ким): {decrypted[32:48]}")
    print(f"  Блок 3 (премия Ким): {decrypted[48:64]}")
    print("✅ Лесли получила премию Ким, не зная ключа!")

def demonstrate_cbc_error_propagation():
    print("\n=== РАСПРОСТРАНЕНИЕ ОШИБКИ В CBC ===")
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"Salary: 1000 for Leslie, Salary: 5000 for Kim"
    ciphertext = aes_cbc_encrypt(key, plaintext, iv)
    
    # Портим один байт во втором блоке
    modified_ct = bytearray(ciphertext)
    modified_ct[16] ^= 0xFF  # инвертируем байт во втором блоке
    modified_ct = bytes(modified_ct)
    
    decrypted = aes_cbc_decrypt(key, modified_ct, iv)
    print("Оригинал:", plaintext)
    print("После порчи 1 байта в CBC:", decrypted)
    print("→ Весь остаток текста (начиная с повреждённого блока) испорчен.")

def demonstrate_ctr_bit_error():
    print("\n=== ПОБИТОВАЯ ОШИБКА В CTR (ПОТОКОВЫЙ РЕЖИМ) ===")
    key = os.urandom(16)
    iv = os.urandom(16)
    plaintext = b"Very long message that will survive single bit error in CTR mode"
    ciphertext = aes_ctr_encrypt(key, plaintext, iv)
    
    # Портим один бит в ciphertext
    modified_ct = bytearray(ciphertext)
    modified_ct[5] ^= 0x01
    modified_ct = bytes(modified_ct)
    
    decrypted = aes_ctr_decrypt(key, modified_ct, iv)
    print("Оригинал:", plaintext)
    print("После порчи 1 бита:", decrypted)
    print("→ Испорчен только 1 байт (остальное корректно).")

# ========== ГЛАВНАЯ ФУНКЦИЯ ==========

if __name__ == "__main__":
    key = os.urandom(16)   # AES-128
    iv = os.urandom(16)
    plaintext = b"Hello, world! This is a test message for encryption modes."
    
    print("=== ОБЫЧНОЕ ШИФРОВАНИЕ И РАСШИФРОВАНИЕ ===\n")
    
    # ECB
    ct_ecb = aes_ecb_encrypt(key, plaintext)
    pt_ecb = aes_ecb_decrypt(key, ct_ecb)
    print(f"ECB: {pt_ecb}")
    
    # CBC
    ct_cbc = aes_cbc_encrypt(key, plaintext, iv)
    pt_cbc = aes_cbc_decrypt(key, ct_cbc, iv)
    print(f"CBC: {pt_cbc}")
    
    # CFB
    ct_cfb = aes_cfb_encrypt(key, plaintext, iv)
    pt_cfb = aes_cfb_decrypt(key, ct_cfb, iv)
    print(f"CFB: {pt_cfb}")
    
    # CTR
    ct_ctr = aes_ctr_encrypt(key, plaintext, iv)
    pt_ctr = aes_ctr_decrypt(key, ct_ctr, iv)
    print(f"CTR: {pt_ctr}")
    
    # Демонстрация атак
    demonstrate_ecb_attack()
    demonstrate_cbc_error_propagation()
    demonstrate_ctr_bit_error()
    
    # Предупреждение о повторном использовании (key, IV) в CTR
    print("\n=== ОПАСНОСТЬ ПОВТОРНОГО ИСПОЛЬЗОВАНИЯ (KEY, IV) В CTR ===")
    iv_reused = b'\x00' * 16
    msg1 = b"Secret message for Alice"
    msg2 = b"Confidential data for Bob"
    ct1 = aes_ctr_encrypt(key, msg1, iv_reused)
    ct2 = aes_ctr_encrypt(key, msg2, iv_reused)
    xor_messages = xor_bytes(ct1, ct2)
    print(f"XOR двух шифротекстов (убирает ключевой поток): {xor_messages.hex()}")
    print("Криптоаналитик может восстановить msg1 ⊕ msg2 и атаковать статистически.")