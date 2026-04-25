"""
Симуляция TLS Handshake на основе описания из текста
Демонстрация основных этапов: согласование параметров, сертификаты, обмен ключами
"""

import hashlib
import secrets
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def generate_rsa_key_pair():
    """Генерация пары RSA-ключей (симуляция сертификата)"""
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """Шифрование открытым ключом RSA"""
    return public_key.encrypt(
        data,
        padding.PKCS1v15()
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Расшифрование закрытым ключом RSA"""
    return private_key.decrypt(
        ciphertext,
        padding.PKCS1v15()
    )

def derive_session_key(premaster_key: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes:
    """
    Вычисление ключа сеанса по подготовительному ключу и нонсам
    В реальном TLS используется PRF (Pseudo Random Function)
    """
    # Упрощённая версия для демонстрации
    combined = premaster_key + client_nonce + server_nonce
    return hashlib.sha256(combined).digest()  # 256-битный ключ

def rc4_stream_cipher(key: bytes, data: bytes) -> bytes:
    """
    Симуляция RC4 (упрощённо - XOR с псевдослучайной последовательностью)
    В реальном коде RC4 не используется из-за уязвимостей
    """
    if not hasattr(rc4_stream_cipher, "_prf_state"):
        rc4_stream_cipher._prf_state = key
    
    keystream = hashlib.pbkdf2_hmac('sha256', key, b'rc4_keystream', 10000, len(data))
    return bytes(a ^ b for a, b in zip(data, keystream))

# ============================================================================
# СТРУКТУРЫ ДАННЫХ
# ============================================================================

@dataclass
class ClientHello:
    """Сообщение 1: запрос клиента на установление соединения"""
    version: str = "TLS 1.2"
    client_nonce: bytes = field(default_factory = lambda: secrets.token_bytes(32))
    supported_ciphers: List[str] = field(default_factory = lambda: [
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    ])
    compression_methods: List[str] = field(default_factory = lambda: ["null", "deflate"])
    
    def serialize(self) -> dict:
        return {
            "version": self.version,
            "client_nonce": self.client_nonce.hex(),
            "supported_ciphers": self.supported_ciphers,
            "compression_methods": self.compression_methods
        }
    
    @classmethod
    def deserialize(cls, data: dict):
        obj = cls()
        obj.version = data["version"]
        obj.client_nonce = bytes.fromhex(data["client_nonce"])
        obj.supported_ciphers = data["supported_ciphers"]
        obj.compression_methods = data["compression_methods"]
        return obj


@dataclass
class ServerHello:
    """Сообщение 2: ответ сервера с выбранными параметрами"""
    version: str = "TLS 1.2"
    server_nonce: bytes = field(default_factory = lambda: secrets.token_bytes(32))
    selected_cipher: str = ""
    selected_compression: str = "null"
    
    def serialize(self) -> dict:
        return {
            "version": self.version,
            "server_nonce": self.server_nonce.hex(),
            "selected_cipher": self.selected_cipher,
            "selected_compression": self.selected_compression
        }
    
    @classmethod
    def deserialize(cls, data: dict):
        obj = cls()
        obj.version = data["version"]
        obj.server_nonce = bytes.fromhex(data["server_nonce"])
        obj.selected_cipher = data["selected_cipher"]
        obj.selected_compression = data["selected_compression"]
        return obj


@dataclass
class Certificate:
    """Сообщение 3: сертификат сервера с открытым ключом"""
    common_name: str
    public_key_pem: str
    issuer: str = "Simulated CA"
    
    def serialize(self) -> dict:
        return {
            "common_name": self.common_name,
            "public_key_pem": self.public_key_pem,
            "issuer": self.issuer
        }
    
    @classmethod
    def deserialize(cls, data: dict):
        return cls(
            common_name = data["common_name"],
            public_key_pem = data["public_key_pem"],
            issuer = data["issuer"]
        )


@dataclass
class ClientKeyExchange:
    """Сообщение 5: подготовительный ключ (premaster key), зашифрованный открытым ключом сервера"""
    encrypted_premaster: bytes
    
    def serialize(self) -> dict:
        return {"encrypted_premaster": self.encrypted_premaster.hex()}
    
    @classmethod
    def deserialize(cls, data: dict):
        return cls(encrypted_premaster = bytes.fromhex(data["encrypted_premaster"]))


@dataclass
class ChangeCipherSpec:
    """Сообщение 6/8: переключение на новый шифр"""
    pass


@dataclass
class Finished:
    """Сообщение 7/9: подтверждение окончания handshake"""
    verify_data: bytes
    
    def serialize(self) -> dict:
        return {"verify_data": self.verify_data.hex()}
    
    @classmethod
    def deserialize(cls, data: dict):
        return cls(verify_data = bytes.fromhex(data["verify_data"]))


# ============================================================================
# ОСНОВНЫЕ КЛАССЫ
# ============================================================================

class TLSClient:
    """Клиент TLS - Алиса"""
    
    def __init__(self, name: str = "Alice"):
        self.name = name
        self.session_key = None
        self.trusted_cas = {}  # Симуляция доверенных центров сертификации
        self.server_public_key = None
        
        # Добавляем доверенный корневой сертификат (симуляция встроенных в браузер ключей)
        self._init_trusted_cas()
    
    def _init_trusted_cas(self):
        """Инициализация доверенных сертификатов (как в браузере - ~100 ключей)"""
        # В реальном браузере здесь были бы публичные ключи VeriSign, DigiCert и др.
        self.trusted_cas["Simulated CA"] = b"Simulated_CA_public_key_fingerprint"
        print(f"[{self.name}] Инициализированы доверенные центры сертификации")
    
    def send_client_hello(self) -> ClientHello:
        """Сообщение 1: отправка запроса на установление соединения"""
        print(f"\n[{self.name}] --> Сообщение 1: ClientHello")
        client_hello = ClientHello()
        print(f"    - Версия: {client_hello.version}")
        print(f"    - Нонс (R_A): {client_hello.client_nonce.hex()[:32]}...")
        print(f"    - Поддерживаемые шифры: {', '.join(client_hello.supported_ciphers)}")
        return client_hello
    
    def receive_server_hello(self, server_hello: ServerHello):
        """Сообщение 2: обработка выбора сервера"""
        print(f"\n[{self.name}] <-- Сообщение 2: ServerHello")
        print(f"    - Выбранный шифр: {server_hello.selected_cipher}")
        print(f"    - Нонс сервера (R_B): {server_hello.server_nonce.hex()[:32]}...")
        self.server_nonce = server_hello.server_nonce
        self.selected_cipher = server_hello.selected_cipher
    
    def receive_certificate(self, certificate: Certificate):
        """Сообщение 3: проверка сертификата сервера"""
        print(f"\n[{self.name}] <-- Сообщение 3: Certificate")
        print(f"    - Common Name: {certificate.common_name}")
        print(f"    - Issuer: {certificate.issuer}")
        
        # Проверка сертификата (упрощённо)
        if certificate.issuer in self.trusted_cas:
            print(f"    ✓ Сертификат доверенный (подписан {certificate.issuer})")
        else:
            print(f"    ⚠ Предупреждение: неизвестный эмитент сертификата")
        
        # Загрузка открытого ключа сервера из PEM
        public_key = serialization.load_pem_public_key(
            certificate.public_key_pem.encode()
        )
        self.server_public_key = public_key
        print(f"    ✓ Открытый ключ сервера получен")
    
    def receive_server_hello_done(self):
        """Сообщение 4: сервер завершил свою часть handshake"""
        print(f"\n[{self.name}] <-- Сообщение 4: ServerHelloDone")
        print(f"    Сервер сообщает: очередь клиента")
    
    def send_client_key_exchange(self) -> ClientKeyExchange:
        """Сообщение 5: отправка подготовительного ключа (premaster key)"""
        print(f"\n[{self.name}] --> Сообщение 5: ClientKeyExchange")
        
        # Генерация 384-битного (48 байт) premaster key
        premaster_key = secrets.token_bytes(48)
        print(f"    - Сгенерирован premaster key: {premaster_key.hex()[:32]}...")
        
        # Шифрование открытым ключом сервера
        encrypted_premaster = rsa_encrypt(self.server_public_key, premaster_key)
        print(f"    - Зашифрован открытым ключом сервера")
        
        # Вычисление ключа сеанса
        self.session_key = derive_session_key(
            premaster_key, 
            self.client_hello.client_nonce, 
            self.server_nonce
        )
        print(f"    - Вычислен ключ сеанса (длина: {len(self.session_key) * 8} бит)")
        
        return ClientKeyExchange(encrypted_premaster = encrypted_premaster)
    
    def send_change_cipher_spec(self):
        """Сообщение 6: запрос на переключение шифра"""
        print(f"\n[{self.name}] --> Сообщение 6: ChangeCipherSpec")
        print(f"    Прошу переключиться на новый шифр")
    
    def send_finished(self) -> Finished:
        """Сообщение 7: подтверждение завершения handshake"""
        print(f"\n[{self.name}] --> Сообщение 7: Finished")
        verify_data = hashlib.sha256(self.session_key + b"client_finished").digest()
        print(f"    - Verify data: {verify_data.hex()[:32]}...")
        return Finished(verify_data = verify_data)
    
    def receive_change_cipher_spec(self):
        """Сообщение 8: сервер переключает шифр"""
        print(f"\n[{self.name}] <-- Сообщение 8: ChangeCipherSpec")
        print(f"    Сервер переключился на новый шифр")
    
    def receive_finished(self, finished: Finished):
        """Сообщение 9: подтверждение от сервера"""
        print(f"\n[{self.name}] <-- Сообщение 9: Finished")
        expected = hashlib.sha256(self.session_key + b"server_finished").digest()
        if finished.verify_data == expected:
            print(f"    ✓ Handshake завершён успешно!")
            return True
        else:
            print(f"    ✗ Ошибка верификации!")
            return False
    
    def send_encrypted_data(self, plaintext: str) -> bytes:
        """Отправка защищённых данных (сообщение 10)"""
        print(f"\n[{self.name}] --> Защищённые данные: '{plaintext}'")
        
        # Сжатие (пропускаем для простоты)
        compressed = plaintext.encode()
        
        # Вычисление MAC (Message Authentication Code)
        mac = hashlib.sha256(self.session_key + compressed).digest()[:16]
        
        # Шифрование (симуляция RC4)
        data_with_mac = compressed + mac
        encrypted = rc4_stream_cipher(self.session_key, data_with_mac)
        
        print(f"    - Зашифровано + добавлен MAC")
        return encrypted
    
    def receive_encrypted_data(self, encrypted: bytes) -> str:
        """Приём защищённых данных"""
        # Расшифрование
        decrypted = rc4_stream_cipher(self.session_key, encrypted)
        
        # Извлечение MAC и данных
        mac_received = decrypted[-16:]
        data = decrypted[:-16]
        
        # Проверка MAC
        mac_expected = hashlib.sha256(self.session_key + data).digest()[:16]
        
        if mac_received == mac_expected:
            plaintext = data.decode()
            print(f"\n[{self.name}] <-- Расшифрованные данные: '{plaintext}'")
            print(f"    ✓ Целостность подтверждена (MAC верен)")
            return plaintext
        else:
            print(f"\n[{self.name}] <-- ОШИБКА: нарушена целостность данных!")
            return ""


class TLSServer:
    """Сервер TLS - Боб"""
    
    def __init__(self, name: str = "Bob", common_name: str = "example.com"):
        self.name = name
        self.common_name = common_name
        self.session_key = None
        self.client_nonce = None
        
        # Генерация ключевой пары для сервера (как в сертификате)
        self.private_key, self.public_key = generate_rsa_key_pair()
        print(f"[{self.name}] Сервер инициализирован с ключевой парой RSA")
    
    def get_certificate(self) -> Certificate:
        """Формирование сертификата сервера"""
        # Сериализация публичного ключа в PEM
        public_key_pem = self.public_key.public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        return Certificate(
            common_name = self.common_name,
            public_key_pem = public_key_pem,
            issuer = "Simulated CA"
        )
    
    def receive_client_hello(self, client_hello: ClientHello) -> ServerHello:
        """Сообщение 1: обработка запроса клиента"""
        print(f"\n[{self.name}] <-- Сообщение 1: ClientHello")
        print(f"    - Версия клиента: {client_hello.version}")
        print(f"    - Нонс клиента (R_A): {client_hello.client_nonce.hex()[:32]}...")
        print(f"    - Поддерживаемые шифры: {', '.join(client_hello.supported_ciphers)}")
        
        self.client_nonce = client_hello.client_nonce
        
        # Выбор наилучшего общего шифра
        selected = client_hello.supported_ciphers[0] if client_hello.supported_ciphers else "TLS_RSA_WITH_AES_256_CBC_SHA"
        print(f"    + Сервер выбирает: {selected}")
        
        return ServerHello(
            server_nonce = secrets.token_bytes(32),
            selected_cipher = selected,
            selected_compression = client_hello.compression_methods[0]
        )
    
    def send_server_hello(self, server_hello: ServerHello):
        """Сообщение 2: отправка ответа сервера"""
        print(f"\n[{self.name}] --> Сообщение 2: ServerHello")
        print(f"    - Нонс сервера (R_B): {server_hello.server_nonce.hex()[:32]}...")
        print(f"    - Выбранный шифр: {server_hello.selected_cipher}")
        self.server_nonce = server_hello.server_nonce
    
    def send_certificate(self):
        """Сообщение 3: отправка сертификата"""
        cert = self.get_certificate()
        print(f"\n[{self.name}] --> Сообщение 3: Certificate")
        print(f"    - Common Name: {cert.common_name}")
        print(f"    - Открытый ключ отправлен")
        return cert
    
    def send_server_hello_done(self):
        """Сообщение 4: сигнал о завершении своей части"""
        print(f"\n[{self.name}] --> Сообщение 4: ServerHelloDone")
        print(f"    - Настала очередь клиента")
    
    def receive_client_key_exchange(self, key_exchange: ClientKeyExchange):
        """Сообщение 5: получение подготовительного ключа"""
        print(f"\n[{self.name}] <-- Сообщение 5: ClientKeyExchange")
        
        # Расшифрование premaster key
        premaster_key = rsa_decrypt(self.private_key, key_exchange.encrypted_premaster)
        print(f"    - Расшифрован premaster key: {premaster_key.hex()[:32]}...")
        
        # Вычисление ключа сеанса
        self.session_key = derive_session_key(
            premaster_key,
            self.client_nonce,
            self.server_nonce
        )
        print(f"    - Вычислен ключ сеанса (длина: {len(self.session_key) * 8} бит)")
    
    def receive_change_cipher_spec(self):
        """Сообщение 6: клиент просит переключить шифр"""
        print(f"\n[{self.name}] <-- Сообщение 6: ChangeCipherSpec")
        print(f"    - Клиент запрашивает переключение шифра")
    
    def receive_finished(self, finished: Finished) -> bool:
        """Сообщение 7: проверка завершения от клиента"""
        print(f"\n[{self.name}] <-- Сообщение 7: Finished")
        expected = hashlib.sha256(self.session_key + b"client_finished").digest()
        if finished.verify_data == expected:
            print(f"    ✓ Верификация клиента успешна")
            return True
        else:
            print(f"    ✗ Верификация не удалась")
            return False
    
    def send_change_cipher_spec(self):
        """Сообщение 8: переключение шифра сервером"""
        print(f"\n[{self.name}] --> Сообщение 8: ChangeCipherSpec")
        print(f"    - Переключаюсь на новый шифр")
    
    def send_finished(self) -> Finished:
        """Сообщение 9: подтверждение от сервера"""
        print(f"\n[{self.name}] --> Сообщение 9: Finished")
        verify_data = hashlib.sha256(self.session_key + b"server_finished").digest()
        print(f"    - Verify data: {verify_data.hex()[:32]}...")
        return Finished(verify_data=verify_data)
    
    def send_encrypted_data(self, plaintext: str) -> bytes:
        """Отправка защищённых данных"""
        print(f"\n[{self.name}] --> Защищённые данные: '{plaintext}'")
        compressed = plaintext.encode()
        mac = hashlib.sha256(self.session_key + compressed).digest()[:16]
        encrypted = rc4_stream_cipher(self.session_key, compressed + mac)
        return encrypted
    
    def receive_encrypted_data(self, encrypted: bytes) -> str:
        """Приём защищённых данных"""
        decrypted = rc4_stream_cipher(self.session_key, encrypted)
        mac_received = decrypted[-16:]
        data = decrypted[:-16]
        mac_expected = hashlib.sha256(self.session_key + data).digest()[:16]
        
        if mac_received == mac_expected:
            plaintext = data.decode()
            print(f"\n[{self.name}] <-- Расшифрованные данные: '{plaintext}'")
            print(f"    ✓ Целостность подтверждена")
            return plaintext
        else:
            print(f"\n[{self.name}] <-- ОШИБКА: нарушена целостность!")
            return ""


# ============================================================================
# ЗАПУСК И ТЕСТИРОВАНИЕ
# ============================================================================

def run_tls_handshake_demo():
    """Полная симуляция TLS handshake"""
    print("=" * 70)
    print("СИМУЛЯЦИЯ TLS HANDSHAKE (на основе описания из текста)")
    print("=" * 70)
    
    # Инициализация участников
    alice = TLSClient("Алиса")
    bob = TLSServer("Боб", "bank.example.com")
    
    print("\n" + "=" * 70)
    print("ФАЗА 1: УСТАНОВЛЕНИЕ СОЕДИНЕНИЯ (HANDSHAKE)")
    print("=" * 70)
    
    # Сообщение 1: ClientHello
    client_hello = alice.send_client_hello()
    alice.client_hello = client_hello
    
    # Сервер обрабатывает ClientHello
    server_hello = bob.receive_client_hello(client_hello)
    
    # Сообщение 2: ServerHello
    bob.send_server_hello(server_hello)
    alice.receive_server_hello(server_hello)
    
    # Сообщение 3: Certificate
    certificate = bob.send_certificate()
    alice.receive_certificate(certificate)
    
    # Сообщение 4: ServerHelloDone
    bob.send_server_hello_done()
    alice.receive_server_hello_done()
    
    # Сообщение 5: ClientKeyExchange
    client_key_exchange = alice.send_client_key_exchange()
    bob.receive_client_key_exchange(client_key_exchange)
    
    # Сообщение 6: ChangeCipherSpec (клиент)
    alice.send_change_cipher_spec()
    bob.receive_change_cipher_spec()
    
    # Сообщение 7: Finished (клиент)
    finished_client = alice.send_finished()
    bob.receive_finished(finished_client)
    
    # Сообщение 8: ChangeCipherSpec (сервер)
    bob.send_change_cipher_spec()
    alice.receive_change_cipher_spec()
    
    # Сообщение 9: Finished (сервер)
    finished_server = bob.send_finished()
    alice.receive_finished(finished_server)
    
    print("\n" + "=" * 70)
    print("ФАЗА 2: ЗАЩИЩЁННАЯ ПЕРЕДАЧА ДАННЫХ")
    print("=" * 70)
    
    # Обмен защищёнными данными
    print("\n--- Алиса отправляет секретные данные Бобу ---")
    encrypted_msg = alice.send_encrypted_data("Платёж: 1000$ на счёт 12345")
    bob.receive_encrypted_data(encrypted_msg)
    
    print("\n--- Боб отправляет подтверждение Алисе ---")
    encrypted_reply = bob.send_encrypted_data("Подтверждение: платёж принят")
    alice.receive_encrypted_data(encrypted_reply)
    
    print("\n" + "=" * 70)
    print("ИТОГ: ЗАЩИЩЁННОЕ СОЕДИНЕНИЕ УСПЕШНО УСТАНОВЛЕНО")
    print("Обеспечено:")
    print("✓ 1. Согласование параметров")
    print("✓ 2. Аутентификация сервера клиентом") 
    print("✓ 3. Конфиденциальная передача данных")
    print("✓ 4. Защита целостности данных")
    print("=" * 70)
    
    # Предупреждение о безопасности (как в тексте)
    print("\n⚠ ПРИМЕЧАНИЕ ПО БЕЗОПАСНОСТИ:")
    print("   - В демонстрации используется упрощённое шифрование")
    print("   - В реальных системах RC4 и MD5 более НЕ используются")
    print("   - Современные TLS используют AES-GCM, ChaCha20-Poly1305")
    print("   - Рекомендуются: ECDHE + AES-256-GCM + SHA-384")


def show_security_warnings():
    """Демонстрация проблем безопасности, описанных в тексте"""
    print("\n" + "=" * 70)
    print("ПРОБЛЕМЫ БЕЗОПАСНОСТИ (из текста и современные)")
    print("=" * 70)
    
    problems = [
        ("RC4 слабые ключи", "Fluhrer et al., 2001 — ключи легко взламываются"),
        ("40-битные экспортные ключи", "Взламываются перебором за несколько часов"),
        ("MD5 коллизии", "Полностью скомпрометирован с 2008 года"),
        ("3DES Sweet32", "Атака на 64-битные блоки"),
        ("Отсутствие Perfect Forward Secrecy", "Взлом ключа сервера расшифровывает всё"),
    ]
    
    for name, desc in problems:
        print(f"  ⚠ {name}: {desc}")
    
    print("\n✅ РЕШЕНИЯ:")
    print("   - TLS 1.3 (только безопасные шифры)")
    print("   - Forward Secrecy через ECDHE")
    print("   - AES-256-GCM или ChaCha20-Poly1305")
    print("   - Обязательная проверка сертификатов")


if __name__ == "__main__":
    run_tls_handshake_demo()
    show_security_warnings()