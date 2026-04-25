"""
Демонстрация основных механизмов S/MIME (упрощённая, но рабочая):
- Генерация ключей и самоподписанного сертификата
- Подпись сообщения (RSA + SHA256)
- Проверка подписи
- Шифрование сообщения (гибридное: AES + RSA)
- Расшифрование
"""

import datetime
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding


def generate_self_signed_cert(email, key_size = 2048):
    """Генерирует RSA-ключи и самоподписанный сертификат X.509 для email."""
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = key_size,
        backend = default_backend()
    )
    
    # Используем timezone-aware datetime для устранения предупреждения
    now = datetime.datetime.now(datetime.timezone.utc)
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, email),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days = 365))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical = False)
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    return private_key, cert


def save_key_and_cert(private_key, cert, name_base):
    """Сохраняет закрытый ключ и сертификат в файлы PEM."""
    with open(f"{name_base}_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.PKCS8,
            encryption_algorithm = serialization.NoEncryption()
        ))
    with open(f"{name_base}_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def sign_message(message_bytes, private_key):
    """
    Создаёт цифровую подпись сообщения (RSA + SHA256).
    Аналог подписи в S/MIME.
    """
    signature = private_key.sign(
        message_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature


def verify_signature(message_bytes, signature, public_key):
    """
    Проверяет цифровую подпись сообщения.
    """
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Ошибка проверки подписи: {e}")
        return False


def encrypt_message(message_bytes, recipient_public_key):
    """
    Гибридное шифрование: AES-256 (CBC) для сообщения, RSA для ключа.
    Аналог enveloped-data в S/MIME.
    """
    # Генерируем случайный AES ключ и IV
    aes_key = os.urandom(32)  # AES-256
    iv = os.urandom(16)       # для CBC режима
    
    # Шифруем сообщение AES-256-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    
    # Добавляем padding (PKCS7)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message_bytes) + padder.finalize()
    
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    
    # Шифруем AES ключ с помощью RSA публичного ключа получателя
    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.PKCS1v15()
    )
    
    # Формат: [длина зашифрованного ключа (4 байта)] + [зашифрованный ключ] + [IV] + [зашифрованное сообщение]
    key_length = len(encrypted_aes_key).to_bytes(4, 'big')
    result = key_length + encrypted_aes_key + iv + encrypted_message
    
    return result


def decrypt_message(encrypted_data, private_key):
    """
    Расшифровывает сообщение, зашифрованное функцией encrypt_message.
    """
    # Извлекаем компоненты
    key_length = int.from_bytes(encrypted_data[:4], 'big')
    encrypted_aes_key = encrypted_data[4:4 + key_length]
    iv = encrypted_data[4 + key_length:4 + key_length + 16]
    encrypted_message = encrypted_data[4 + key_length + 16:]
    
    # Расшифровываем AES ключ с помощью RSA приватного ключа
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.PKCS1v15()
    )
    
    # Расшифровываем сообщение AES-256-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
    
    # Убираем padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted


# ------------------- Демонстрация -------------------
def main():
    print("=== Демонстрация принципов S/MIME ===\n")
    
    # 1. Генерируем ключи и сертификаты для Алисы и Боба
    print("1. Генерация ключей и сертификатов (якори доверия)")
    alice_key, alice_cert = generate_self_signed_cert("alice@example.com")
    bob_key, bob_cert = generate_self_signed_cert("bob@example.com")
    save_key_and_cert(alice_key, alice_cert, "alice")
    save_key_and_cert(bob_key, bob_cert, "bob")
    print("   Сертификаты сохранены: alice_cert.pem, bob_cert.pem")
    
    # 2. Алиса подписывает сообщение для Боба
    print("\n2. Алиса подписывает сообщение для Боба")
    original_message = "Привет, Боб! Это секретное сообщение от Алисы.".encode('utf-8')
    print(f"   Исходное сообщение: {original_message.decode('utf-8')}")
    
    signature = sign_message(original_message, alice_key)
    print(f"   Подпись создана (RSA+SHA256), размер {len(signature)} байт")
    
    # 3. Боб проверяет подпись, используя публичный ключ из сертификата Алисы
    print("\n3. Боб проверяет подпись, используя сертификат Алисы")
    alice_public_key = alice_cert.public_key()
    is_valid = verify_signature(original_message, signature, alice_public_key)
    print(f"   Подпись верна: {is_valid}")
    
    # 4. Боб шифрует ответное сообщение для Алисы
    print("\n4. Боб шифрует сообщение для Алисы (используя её публичный ключ)")
    reply_message = "Привет, Алиса! Подпись проверил, всё ок.".encode('utf-8')
    
    alice_public_key = alice_cert.public_key()
    encrypted = encrypt_message(reply_message, alice_public_key)
    print(f"   Зашифровано (гибридное: AES-256 + RSA), размер {len(encrypted)} байт")
    
    # 5. Алиса расшифровывает сообщение
    print("\n5. Алиса расшифровывает сообщение своим закрытым ключом")
    decrypted = decrypt_message(encrypted, alice_key)
    if decrypted:
        print(f"   Расшифрованное сообщение: {decrypted.decode('utf-8')}")
    else:
        print("   Расшифровка не удалась")
    
    # 6. Тест нарушения целостности
    print("\n6. Тест нарушения целостности")
    tampered_message = "Привет, Боб! Это секретное сообщение от Алисы (ВЗЛОМАНО!).".encode('utf-8')
    is_valid_tampered = verify_signature(tampered_message, signature, alice_public_key)
    print(f"   Проверка подписи для изменённого сообщения: {is_valid_tampered}")
    
    # 7. Демонстрация аутентификации (личность подтверждена сертификатом)
    print("\n7. Информация о сертификате отправителя (аутентификация)")
    print(f"   Владелец: {alice_cert.subject.rfc4514_string()}")
    print(f"   Email: {alice_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.RFC822Name)[0]}")
    print(f"   Серийный номер: {alice_cert.serial_number}")
    
    print("\n=== Завершено ===")
    print("\nПояснение:")
    print("- Цифровая подпись обеспечивает целостность и аутентификацию")
    print("- Гибридное шифрование (AES+RSA) обеспечивает конфиденциальность")
    print("- Сертификаты X.509 служат 'якорями доверия'")
    print("- В реальном S/MIME всё это упаковывается в MIME-контейнеры")


if __name__ == "__main__":
    main()