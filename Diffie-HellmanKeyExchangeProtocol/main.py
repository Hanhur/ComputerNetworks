import hashlib
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ========== Вспомогательные функции ==========

def generate_large_prime(bits = 256):
    """Генерирует простое число (упрощённо, для демонстрации)."""
    # В реальности используют библиотеки типа `sympy` или `cryptography`
    # Здесь для примера возьмём фиксированное простое число, чтобы код работал сразу
    # В DH нужны очень большие простые числа, но для демонстрации подойдёт и 256-битное.
    # Возвращаем известное простое число из RFC 3526 (2048-битное слишком большое, возьмём 256-битное)
    # Но для простоты примера используем небольшое простое, но с условием, что (p-1)/2 тоже простое.
    # Фиксированные параметры (для повторяемости примера):
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    return p, g

def dh_public_key(private_key, p, g):
    """Вычисляет открытый ключ: g^private mod p"""
    return pow(g, private_key, p)

def dh_shared_secret(private_key, other_public_key, p):
    """Вычисляет общий секрет: other_public_key^private mod p"""
    return pow(other_public_key, private_key, p)

def derive_key_from_shared_secret(shared_secret_int):
    """Преобразует общий секрет (число) в ключ для Fernet (32 байта base64)."""
    shared_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, 'big')
    # Используем PBKDF2 для получения ключа нужной длины
    salt = b'dh_salt'  # В реальности соль должна быть случайной и передаваться, но для демо фиксирована
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = 100000,
    )
    key_bytes = kdf.derive(shared_bytes)
    return Fernet(base64.urlsafe_b64encode(key_bytes))

import base64

# ========== Честный обмен (без MitM) ==========

def honest_dh_exchange():
    print("\n" + "=" * 60)
    print("1. ЧЕСТНЫЙ ОБМЕН ДИФФИ–ХЕЛЛМАНА (без посредника)")
    print("=" * 60)
    
    p, g = generate_large_prime()
    print(f"Открытые параметры (p, g):")
    print(f"p = {p}")
    print(f"g = {g}")
    
    # Алиса и Боб генерируют секретные ключи
    alice_private = secrets.randbelow(p - 1) + 1
    bob_private = secrets.randbelow(p - 1) + 1
    
    print(f"\nСекретные ключи (никто не знает):")
    print(f"Алиса: x = {alice_private}")
    print(f"Боб:   y = {bob_private}")
    
    # Обмен открытыми ключами
    alice_public = dh_public_key(alice_private, p, g)
    bob_public = dh_public_key(bob_private, p, g)
    
    print(f"\nОбмен открытыми ключами (видят все, включая Труди):")
    print(f"Алиса -> Боб: g^x mod p = {alice_public}")
    print(f"Боб   -> Алиса: g^y mod p = {bob_public}")
    
    # Вычисление общего секрета
    alice_shared = dh_shared_secret(alice_private, bob_public, p)
    bob_shared = dh_shared_secret(bob_private, alice_public, p)
    
    print(f"\nОбщий секрет (должен совпадать):")
    print(f"Алиса вычислила: g^(xy) mod p = {alice_shared}")
    print(f"Боб вычислил:    g^(yx) mod p = {bob_shared}")
    
    assert alice_shared == bob_shared, "Ошибка: секреты не совпадают!"
    
    # Шифрование сообщения
    alice_key = derive_key_from_shared_secret(alice_shared)
    bob_key = derive_key_from_shared_secret(bob_shared)
    
    message = "Привет, Боб! Это секретное сообщение."
    encrypted = alice_key.encrypt(message.encode())
    print(f"\nАлиса шифрует: '{message}'")
    print(f"Зашифрованное сообщение: {encrypted}")
    
    decrypted = bob_key.decrypt(encrypted).decode()
    print(f"Боб расшифровал: '{decrypted}'")
    
    return True

# ========== Атака "Человек посередине" ==========

def mitm_attack_demo():
    print("\n" + "=" * 60)
    print("2. АТАКА «ЧЕЛОВЕК ПОСЕРЕДИНЕ» (Man-in-the-Middle)")
    print("=" * 60)
    
    p, g = generate_large_prime()
    print(f"Открытые параметры (p, g):")
    print(f"p = {p}")
    print(f"g = {g}")
    
    # Генерация секретных ключей
    alice_private = secrets.randbelow(p - 1) + 1
    bob_private = secrets.randbelow(p - 1) + 1
    trudy_private = secrets.randbelow(p - 1) + 1  # Секретный ключ Труди
    
    print(f"\nСекретные ключи:")
    print(f"Алиса: x = {alice_private}")
    print(f"Боб:   y = {bob_private}")
    print(f"Труди: z = {trudy_private} (злоумышленник)")
    
    # Открытые ключи
    alice_public = dh_public_key(alice_private, p, g)
    bob_public = dh_public_key(bob_private, p, g)
    trudy_public = dh_public_key(trudy_private, p, g)
    
    print(f"\nОткрытые ключи (честные):")
    print(f"Алиса: {alice_public}")
    print(f"Боб:   {bob_public}")
    print(f"Труди: {trudy_public}")
    
    # --- ПЕРЕХВАТ И ПОДМЕНА ---
    print("\n" + "-" * 40)
    print("Труди перехватывает и подменяет открытые ключи:")
    print("-" * 40)
    
    # Алиса отправляет свой открытый ключ Бобу, но Труди перехватывает
    # и отправляет Бобу СВОЙ открытый ключ
    bob_receives_from_alice = trudy_public  # Подмена!
    
    # Боб отправляет свой открытый ключ Алисе, Труди подменяет на свой
    alice_receives_from_bob = trudy_public  # Подмена!
    
    print(f"Алиса думает, что отправила Бобу {alice_public}, но Боб получил {bob_receives_from_alice}")
    print(f"Боб думает, что отправил Алисе {bob_public}, но Алиса получила {alice_receives_from_bob}")
    
    # --- ВЫЧИСЛЕНИЕ СЕКРЕТОВ ---
    # Алиса вычисляет секрет с тем, кого считает Бобом (на самом деле с Труди)
    alice_shared_with_trudy = dh_shared_secret(alice_private, alice_receives_from_bob, p)
    
    # Боб вычисляет секрет с тем, кого считает Алисой (на самом деле с Труди)
    bob_shared_with_trudy = dh_shared_secret(bob_private, bob_receives_from_alice, p)
    
    # Труди вычисляет два секрета: для общения с Алисой и с Бобом
    trudy_shared_with_alice = dh_shared_secret(trudy_private, alice_public, p)
    trudy_shared_with_bob = dh_shared_secret(trudy_private, bob_public, p)
    
    print(f"\nВычисленные общие секреты:")
    print(f"Алиса думает, что её секрет с Бобом = {alice_shared_with_trudy}")
    print(f"Боб думает, что его секрет с Алисой = {bob_shared_with_trudy}")
    print(f"Труди с Алисой: {trudy_shared_with_alice}")
    print(f"Труди с Бобом:   {trudy_shared_with_bob}")
    
    # Проверка: секрет Алисы = секрету Труди (для их пары)
    assert alice_shared_with_trudy == trudy_shared_with_alice, "Ошибка: секрет Алисы-Труди не совпадает"
    assert bob_shared_with_trudy == trudy_shared_with_bob, "Ошибка: секрет Боба-Труди не совпадает"
    
    print("\n*** Труди теперь имеет два отдельных общих секрета: с Алисой и с Бобом ***")
    
    # --- ПЕРЕХВАТ СООБЩЕНИЙ ---
    print("\n" + "-" * 40)
    print("Труди перехватывает и расшифровывает сообщения:")
    print("-" * 40)
    
    # Создаём ключи шифрования
    alice_key = derive_key_from_shared_secret(alice_shared_with_trudy)
    bob_key = derive_key_from_shared_secret(bob_shared_with_trudy)
    trudy_key_with_alice = derive_key_from_shared_secret(trudy_shared_with_alice)
    trudy_key_with_bob = derive_key_from_shared_secret(trudy_shared_with_bob)
    
    # Алиса отправляет сообщение Бобу (думая, что канал защищён)
    alice_message = "Боб, переведи мне 1000 долларов на счёт 12345"
    encrypted_by_alice = alice_key.encrypt(alice_message.encode())
    print(f"\nАлиса отправляет (зашифрованно): {alice_message}")
    print(f"Шифротекст: {encrypted_by_alice}")
    
    # Труди расшифровывает своим ключом (который общий с Алисой)
    decrypted_by_trudy = trudy_key_with_alice.decrypt(encrypted_by_alice).decode()
    print(f"Труди расшифровала: {decrypted_by_trudy}")
    
    # Труди может изменить сообщение
    modified_message = decrypted_by_trudy.replace("1000", "10000").replace("12345", "67890")
    print(f"Труди изменила на: {modified_message}")
    
    # Труди зашифровывает новым ключом (который общий с Бобом) и отправляет Бобу
    encrypted_by_trudy = trudy_key_with_bob.encrypt(modified_message.encode())
    print(f"Труди отправляет Бобу (зашифрованно своим ключом): {encrypted_by_trudy}")
    
    # Боб расшифровывает (думая, что от Алисы)
    decrypted_by_bob = bob_key.decrypt(encrypted_by_trudy).decode()
    print(f"Боб расшифровал и получил: {decrypted_by_bob}")
    
    print("\n" + "!" * 60)
    print("РЕЗУЛЬТАТ АТАКИ: Боб получил изменённое сообщение, хотя думает, что общается напрямую с Алисой.")
    print("Труди прочитала и изменила содержимое, не будучи замеченной.")
    print("!" * 60)

# ========== Запуск ==========

if __name__ == "__main__":
    # Честный обмен
    honest_dh_exchange()
    
    # Атака посредника
    mitm_attack_demo()
    
    print("\n" + "=" * 60)
    print("ВЫВОД: Протокол Диффи–Хеллмана без аутентификации уязвим для атаки «человек посередине».")
    print("Для защиты необходима проверка подлинности открытых ключей (цифровые подписи, PKI).")
    print("=" * 60)