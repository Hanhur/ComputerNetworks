"""
Программа: Профили сообщений (Message Digest) и аутентификация
Основана на концепциях из текста: хеш-функции, свойства MD,
применение для цифровой подписи (симуляция), SHA-1, SHA-2, SHA-3.
"""

import hashlib
import time
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class MessageDigestDemo:
    """
    Демонстрация свойств хеш-функций (профилей сообщений)
    и их применения для аутентификации.
    """

    @staticmethod
    def demonstrate_properties():
        """Демонстрирует 4 ключевых свойства хеш-функции из текста."""
        print("=" * 70)
        print("1. ДЕМОНСТРАЦИЯ СВОЙСТВ ХЕШ-ФУНКЦИИ (SHA-256)")
        print("=" * 70)

        # Исходное сообщение (используем обычные строки и кодируем в UTF-8)
        message1 = "Hello, World!".encode('utf-8')
        message2 = "Hello, World".encode('utf-8')  # Отличается на 1 байт (нет '!')
        message3 = "Different message entirely".encode('utf-8')

        # Свойство 1: Легко вычислить MD(P)
        md1 = hashlib.sha256(message1).hexdigest()
        print(f"\n[Свойство 1] Вычислимость")
        print(f"  Сообщение P: {message1.decode('utf-8')}")
        print(f"  MD(P): {md1}")

        # Свойство 2: Необратимость (демонстрация - невозможно восстановить P из MD)
        print(f"\n[Свойство 2] Необратимость")
        print(f"  Из MD(P) = {md1[:16]}... невозможно восстановить исходное сообщение")

        # Свойство 3: Стойкость к коллизиям (демонстрация с SHA-256 - нет коллизий)
        md2 = hashlib.sha256(message2).hexdigest()
        md3 = hashlib.sha256(message3).hexdigest()
        print(f"\n[Свойство 3] Стойкость к коллизиям")
        print(f"  MD(P1): {md1[:16]}...")
        print(f"  MD(P2): {md2[:16]}...")
        print(f"  MD(P3): {md3[:16]}...")
        print(f"  Все хеши уникальны (для разных сообщений)")

        # Свойство 4: Лавинный эффект (изменение 1 бита)
        print(f"\n[Свойство 4] Лавинный эффект")
        print(f"  MD(Hello, World!): {md1}")
        print(f"  MD(Hello, World) : {md2}")
        different_bits = sum(c1 != c2 for c1, c2 in zip(md1, md2))
        print(f"  Количество отличающихся hex-символов: {different_bits} из {len(md1)}")
        print(f"  Изменение 1 байта во входе изменило ~{different_bits / len(md1) * 100:.1f}% выходных символов")

    @staticmethod
    def compare_speed():
        """Сравнивает скорость хеширования vs шифрования."""
        print("\n" + "=" * 70)
        print("2. СРАВНЕНИЕ СКОРОСТИ: ХЕШИРОВАНИЕ vs ШИФРОВАНИЕ")
        print("=" * 70)

        # Генерируем тестовые данные разного размера
        sizes = [100, 1000, 10000, 100000]
        rsa_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)

        for size in sizes:
            data = b"X" * size

            # Время хеширования (SHA-256)
            start = time.perf_counter()
            hash_result = hashlib.sha256(data).hexdigest()
            hash_time = time.perf_counter() - start

            # Время RSA-шифрования
            start = time.perf_counter()
            # RSA 2048 может зашифровать только ~190 байт
            chunk_size = min(size, 190)
            encrypted = rsa_key.public_key().encrypt(
                data[:chunk_size],
                padding.PKCS1v15()
            )
            rsa_time = time.perf_counter() - start

            print(f"  Размер {size:6d} байт: Хеш={hash_time * 1000:.3f} мс, RSA={rsa_time * 1000:.3f} мс (только {chunk_size} байт)")

        print("\n  Вывод: Хеширование НАМНОГО быстрее шифрования, особенно для больших данных")
        print("  Поэтому в цифровых подписях подписывают хеш, а не всё сообщение.")

    @staticmethod
    def simulate_digital_signature():
        """Симулирует цифровую подпись с использованием профиля сообщения (как на иллюстрации 8.24)."""
        print("\n" + "=" * 70)
        print("3. СИМУЛЯЦИЯ ЦИФРОВОЙ ПОДПИСИ (Алиса → Боб)")
        print("=" * 70)

        # 1. Алиса генерирует ключи
        print("\n[Шаг 1] Алиса генерирует пару ключей (RSA 2048)")
        alice_private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
        alice_public_key = alice_private_key.public_key()

        # 2. Сообщение, которое Алиса хочет подписать (используем UTF-8 строку)
        original_message = "Договор: Алиса продаёт Бобу 100 акций по цене 50$ за штуку.".encode('utf-8')
        print(f"[Шаг 2] Исходное сообщение: {original_message.decode('utf-8')}")

        # 3. Алиса вычисляет профиль сообщения (хеш)
        print(f"[Шаг 3] Алиса вычисляет MD(P) с помощью SHA-256")
        message_hash = hashlib.sha256(original_message).digest()
        print(f"  Хеш: {message_hash.hex()[:40]}...")

        # 4. Алиса подписывает ХЕШ (а не всё сообщение!)
        print(f"[Шаг 4] Алиса подписывает ХЕШ своим закрытым ключом")
        signature = alice_private_key.sign(
            message_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"  Подпись (первые 40 байт): {signature.hex()[:80]}...")

        # 5. Отправка: сообщение + подпись
        print(f"[Шаг 5] Алиса отправляет Бобу: (сообщение, подпись)")

        # 6. Боб получает и проверяет
        print(f"\n[Шаг 6] Боб получает сообщение и проверяет подпись")

        # --- Сценарий А: Честная передача ---
        received_message = original_message
        received_signature = signature

        # Боб вычисляет хеш полученного сообщения
        bob_hash = hashlib.sha256(received_message).digest()

        # Боб проверяет подпись (используя открытый ключ Алисы)
        try:
            alice_public_key.verify(
                received_signature,
                bob_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("  ✓ ПРОВЕРКА УСПЕШНА: Подпись верна, сообщение не изменено")
        except InvalidSignature:
            print("  ✗ ПРОВЕРКА НЕ УДАЛАСЬ: Подпись неверна")

        # --- Сценарий Б: Труди изменяет сообщение ---
        print(f"\n[Сценарий Б: Атака] Труди перехватывает и изменяет сообщение")
        tampered_message = "Договор: Алиса продаёт Бобу 100 акций по цене 1000$ за штуку.".encode('utf-8')
        print(f"  Изменённое сообщение: {tampered_message.decode('utf-8')}")

        bob_hash_tampered = hashlib.sha256(tampered_message).digest()
        try:
            alice_public_key.verify(
                received_signature,
                bob_hash_tampered,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("  ✗ ОШИБКА: Подпись не должна была пройти проверку!")
        except InvalidSignature:
            print("  ✓ ПРОВЕРКА НЕ УДАЛАСЬ: Обнаружена подмена сообщения!")
            print("  (Именно это и гарантирует свойство 3 хеш-функции: нельзя найти P' с таким же MD)")

    @staticmethod
    def compare_sha_families():
        """Сравнивает SHA-1, SHA-2, SHA-3 (как упоминается в тексте)."""
        print("\n" + "=" * 70)
        print("4. СРАВНЕНИЕ SHA-1, SHA-2 и SHA-3")
        print("=" * 70)

        test_message = b"Test message for hash comparison"

        # SHA-1 (взломан в 2017, показан для исторического контекста)
        sha1_hash = hashlib.sha1(test_message).hexdigest()
        print(f"\n[SHA-1] (ВЗЛОМАН в 2017, не использовать!)")
        print(f"  Длина: 160 бит")
        print(f"  Хеш: {sha1_hash}")
        print(f"  Статус: Коллизии найдены на практике → выводится из эксплуатации")

        # SHA-2 семейство
        print(f"\n[SHA-2] (Рекомендуется)")
        sha224 = hashlib.sha224(test_message).hexdigest()
        sha256 = hashlib.sha256(test_message).hexdigest()
        sha384 = hashlib.sha384(test_message).hexdigest()
        sha512 = hashlib.sha512(test_message).hexdigest()

        print(f"  SHA-224 (224 бит): {sha224[:32]}...")
        print(f"  SHA-256 (256 бит): {sha256[:32]}...")
        print(f"  SHA-384 (384 бит): {sha384[:32]}...")
        print(f"  SHA-512 (512 бит): {sha512[:32]}...")
        print(f"  Статус: Безопасен, случаев взлома не зафиксировано")

        # SHA-3 (Keccak)
        print(f"\n[SHA-3] (Keccak, стандарт с 2015)")
        sha3_256 = hashlib.sha3_256(test_message).hexdigest()
        sha3_512 = hashlib.sha3_512(test_message).hexdigest()
        print(f"  SHA3-256: {sha3_256[:32]}...")
        print(f"  SHA3-512: {sha3_512[:32]}...")
        print(f"  Статус: Резервный стандарт на случай атак на SHA-2")

        print(f"\n  ВЫВОД: Не используйте SHA-1. Используйте SHA-256 или SHA-512.")
        print(f"  SHA-3 доступен как альтернатива.")

    @staticmethod
    def demonstrate_collision_resistance():
        """Демонстрирует, почему коллизии опасны (на упрощённом примере)."""
        print("\n" + "=" * 70)
        print("5. ПОЧЕМУ КОЛЛИЗИИ ОПАСНЫ? (Принцип)")
        print("=" * 70)

        print("""
        Если злоумышленник может найти коллизию (P ≠ P', но MD(P) = MD(P')):

        1. Жертва подписывает безобидный документ P:
           Подпись = Sign(ЗакрытыйКлюч, MD(P))

        2. Злоумышленник подменяет P на P' (с тем же хешем!)

        3. Подпись остаётся той же самой, но теперь она «привязана» к P'

        Именно это произошло с SHA-1 в 2017 году:
        Google и CWI создали два разных PDF-файла с одинаковым SHA-1 хешем.
        """)

        # Демонстрация того, что для SHA-256 коллизий пока нет
        doc1 = "Перевести 100 рублей Иванову".encode('utf-8')
        doc2 = "Перевести 1000000 рублей Петрову".encode('utf-8')

        hash1 = hashlib.sha256(doc1).hexdigest()
        hash2 = hashlib.sha256(doc2).hexdigest()

        print(f"  Документ 1: {doc1.decode('utf-8')}")
        print(f"  Документ 2: {doc2.decode('utf-8')}")
        print(f"  Хеш1: {hash1[:24]}...")
        print(f"  Хеш2: {hash2[:24]}...")
        print(f"  Хеши разные (как и должно быть у безопасной хеш-функции)")


class SimpleMessageDigest:
    """
    Упрощённая реализация хеш-функции (только для обучения).
    НЕ КРИПТОГРАФИЧЕСКИ БЕЗОПАСНА!
    Демонстрирует принцип работы.
    """

    def __init__(self, output_size = 32):
        self.output_size = output_size

    def simple_hash(self, message: bytes) -> bytes:
        """
        Очень простая хеш-функция (только для демонстрации принципов).
        НЕ ИСПОЛЬЗОВАТЬ В РЕАЛЬНЫХ СИСТЕМАХ!
        """
        # Инициализируем состояние
        state = [0] * self.output_size

        # Перемешиваем каждый байт сообщения
        for i, byte in enumerate(message):
            state[i % self.output_size] ^= byte
            state[i % self.output_size] = (state[i % self.output_size] + (byte >> 4)) & 0xFF
            # Лавинный эффект: каждый байт влияет на несколько позиций
            for j in range(3):
                idx = (i + j) % self.output_size
                state[idx] = (state[idx] ^ (byte << j)) & 0xFF

        return bytes(state)

    def demonstrate_avalanche(self):
        """Демонстрирует лавинный эффект на простой хеш-функции."""
        print("\n" + "=" * 70)
        print("6. УПРОЩЁННАЯ ХЕШ-ФУНКЦИЯ (демонстрация лавинного эффекта)")
        print("=" * 70)

        msg1 = b"Hello"
        msg2 = b"Hellp"  # Изменён последний символ

        hash1 = self.simple_hash(msg1)
        hash2 = self.simple_hash(msg2)

        print(f"  Сообщение 1: {msg1} -> {hash1.hex()}")
        print(f"  Сообщение 2: {msg2} -> {hash2.hex()}")

        # Считаем количество отличающихся битов
        diff_bits = 0
        for b1, b2 in zip(hash1, hash2):
            diff_bits += bin(b1 ^ b2).count('1')

        print(f"  Количество отличающихся БИТОВ: {diff_bits} из {self.output_size * 8}")
        print(f"  Лавинный эффект: {diff_bits / (self.output_size * 8) * 100:.1f}% битов изменилось")


def main():
    """Главная функция: запускает все демонстрации."""
    print("\n" + "=" * 70)
    print(" ПРОГРАММА: ПРОФИЛИ СООБЩЕНИЙ (MESSAGE DIGEST)")
    print(" Демонстрация концепций из криптографии")
    print("=" * 70)

    demo = MessageDigestDemo()
    simple_hash_demo = SimpleMessageDigest(output_size = 16)

    # Запускаем все демонстрации
    demo.demonstrate_properties()
    demo.compare_speed()
    demo.simulate_digital_signature()
    demo.compare_sha_families()
    demo.demonstrate_collision_resistance()
    simple_hash_demo.demonstrate_avalanche()

    print("\n" + "=" * 70)
    print("ЗАКЛЮЧЕНИЕ (на основе текста)")
    print("=" * 70)
    print("""
    1. Хеш-функции (профили сообщений) обеспечивают аутентификацию без шифрования.
    2. Четыре свойства: вычислимость, необратимость, стойкость к коллизиям, лавинный эффект.
    3. В цифровых подписях подписывается ХЕШ, а не всё сообщение (экономия времени).
    4. SHA-1 — ВЗЛОМАН (2017), не использовать.
    5. SHA-2 (256/512) — современный стандарт.
    6. SHA-3 — резервный стандарт.
    """)


if __name__ == "__main__":
    main()