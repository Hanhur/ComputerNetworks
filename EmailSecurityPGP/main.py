import os
import zlib
import base64
import secrets

# Проверка наличия модуля cryptography
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Ошибка: модуль 'cryptography' не установлен.")
    print("Установите его командой: pip install cryptography")
    exit(1)

# --- 1. ГЕНЕРАЦИЯ КЛЮЧЕЙ ДЛЯ АЛИСЫ И БОБА ---

def generate_rsa_keypair():
    """Генерирует пару RSA-ключей (закрытый/открытый)"""
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Генерируем ключи для Алисы (для подписи) и для Боба (для шифрования сеансового ключа)
print("=== ГЕНЕРАЦИЯ КЛЮЧЕЙ ===")
print("Генерация ключей Алисы...")
alice_private, alice_public = generate_rsa_keypair()
print("Генерация ключей Боба...")
bob_private, bob_public = generate_rsa_keypair()
print("Алиса: закрытый + открытый ключи созданы.")
print("Боб: закрытый + открытый ключи созданы.\n")

# --- 2. ФУНКЦИИ, ОПИСАННЫЕ В ТЕКСТЕ ---

def compress_data(data: bytes) -> bytes:
    """Сжатие (в тексте - Лемпель-Зив, используем zlib)"""
    return zlib.compress(data, level = 9)

def decompress_data(compressed_data: bytes) -> bytes:
    """Распаковка"""
    return zlib.decompress(compressed_data)

def sign_message(message: bytes, private_key) -> bytes:
    """
    Текст: "хеширует сообщение... а затем шифрует полученный хеш ее закрытым RSA-ключом"
    """
    # Хэшируем SHA-256
    hash_algo = hashes.SHA256()
    hasher = hashes.Hash(hash_algo, backend = default_backend())
    hasher.update(message)
    digest = hasher.finalize()
    
    # Шифруем хэш закрытым ключом
    signature = private_key.sign(
        digest,
        padding.PKCS1v15(),
        hash_algo
    )
    return signature

def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    """Проверка подписи открытым ключом"""
    hash_algo = hashes.SHA256()
    hasher = hashes.Hash(hash_algo, backend=default_backend())
    hasher.update(message)
    digest = hasher.finalize()
    
    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hash_algo
        )
        return True
    except Exception:
        return False

def encrypt_aes(data: bytes, key: bytes) -> tuple:
    """Шифрование AES-256 в режиме CFB"""
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(data) + encryptor.finalize()
    return iv, encrypted

def decrypt_aes(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
    """Расшифровка AES"""
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def encrypt_session_key(session_key: bytes, recipient_public_key) -> bytes:
    """Шифрование сеансового ключа открытым ключом получателя"""
    encrypted_key = recipient_public_key.encrypt(
        session_key,
        padding.PKCS1v15()
    )
    return encrypted_key

def decrypt_session_key(encrypted_key: bytes, recipient_private_key) -> bytes:
    """Расшифровка сеансового ключа закрытым ключом"""
    session_key = recipient_private_key.decrypt(
        encrypted_key,
        padding.PKCS1v15()
    )
    return session_key

# --- 3. ОТПРАВКА СООБЩЕНИЯ ОТ АЛИСЫ К БОБУ ---

print("=== АЛИСА ОТПРАВЛЯЕТ СООБЩЕНИЕ ===")
original_message = "Привет, Боб! Это секретное сообщение. Никто, кроме нас, не должен его прочитать."
print(f"Исходное сообщение (P): {original_message}\n")

# Шаг 1: Подпись
message_bytes = original_message.encode('utf-8')
signature = sign_message(message_bytes, alice_private)
print(f"1. Подпись создана (хеш SHA-256, зашифрованный ключом Алисы)")

# Шаг 2: Объединение
combined = message_bytes + b"||SIG||" + signature
print(f"2. Сообщение и подпись объединены")

# Шаг 3: Сжатие
compressed = compress_data(combined)
print(f"3. Сжато: {len(combined)} → {len(compressed)} байт")

# Шаг 4: Сеансовый ключ и шифрование AES
session_key = secrets.token_bytes(32)  # 256 бит
iv, encrypted_data = encrypt_aes(compressed, session_key)
print(f"4. Сгенерирован случайный 256-битный AES-ключ, данные зашифрованы")

# Шаг 5: Шифрование сеансового ключа RSA
encrypted_session_key = encrypt_session_key(session_key, bob_public)
print(f"5. AES-ключ зашифрован открытым ключом Боба")

# Шаг 6: Base64
final_package = encrypted_session_key + iv + encrypted_data
b64_package = base64.b64encode(final_package).decode('ascii')
print(f"6. Всё закодировано в Base64")

print("\n--- ОТПРАВКА ---")
print(f"Бобу отправлен Base64-текст (первые 100 символов):\n{b64_package[:100]}...\n")

# --- 4. ПОЛУЧЕНИЕ И РАСШИФРОВКА ---

print("=== БОБ ПОЛУЧАЕТ И РАСШИФРОВЫВАЕТ ===")

# Шаг 1: Декодирование Base64
received_data = base64.b64decode(b64_package)
print("1. Base64 декодирован")

# Шаг 2: Разделение компонентов
enc_key_len = 256  # Для RSA 2048 бит
encrypted_key_received = received_data[:enc_key_len]
iv_received = received_data[enc_key_len:enc_key_len + 16]
encrypted_data_received = received_data[enc_key_len + 16:]

print("2. Извлечены: зашифрованный ключ, IV, шифротекст")

# Шаг 3: Расшифровка сеансового ключа
decrypted_session_key = decrypt_session_key(encrypted_key_received, bob_private)
print("3. Сеансовый ключ расшифрован закрытым ключом Боба")

# Шаг 4: Расшифровка AES
decrypted_compressed = decrypt_aes(encrypted_data_received, decrypted_session_key, iv_received)
print("4. Данные расшифрованы AES")

# Шаг 5: Распаковка
decompressed = decompress_data(decrypted_compressed)
print("5. Данные распакованы")

# Шаг 6: Разделение сообщения и подписи
parts = decompressed.split(b"||SIG||")
if len(parts) == 2:
    received_message_bytes, received_signature = parts
    received_message = received_message_bytes.decode('utf-8')
    print(f"6. Отделены сообщение и подпись")
    
    # Шаг 7: Проверка подписи
    is_valid = verify_signature(received_message_bytes, received_signature, alice_public)
    
    if is_valid:
        print(f"\n✅ ПОДПИСЬ ВЕРНА. Сообщение действительно от Алисы.")
        print(f"📧 Расшифрованное сообщение: {received_message}")
    else:
        print("\n❌ ПОДПИСЬ НЕВЕРНА! Сообщение могло быть изменено.")
else:
    print("Ошибка: неверный формат.")

# --- 5. ИТОГ ---
print("\n=== СООТВЕТСТВИЕ ТЕКСТУ ИЗ ВАШЕГО ДОКУМЕНТА ===")
print("✅ SHA-2 (256) для хэширования")
print("✅ Шифрование хэша закрытым RSA-ключом (подпись)")
print("✅ Сжатие ZIP (Лемпель-Зив)")
print("✅ Случайный 256-битный AES-ключ сообщения")
print("✅ Шифрование AES-ключа открытым RSA-ключом получателя")
print("✅ Кодировка Base64 для отправки по email")
print("✅ RSA только для малых объёмов (хэш + ключ)")