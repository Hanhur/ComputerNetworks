#!/usr/bin/env python3
"""
DNSSEC Simulator
Демонстрация: подпись RRSET, проверка подписи, защита от спуфинга.
Основано на описании из текста (RFC 4033-4035).
"""

import hashlib
import time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from dataclasses import dataclass
from typing import List, Optional
from datetime import datetime, timedelta

# ------------------------- Модели данных (аналоги RR, RRSET, DNSKEY, RRSIG) -------------------------

@dataclass
class ResourceRecord:
    """Одна DNS-запись (упрощённо)."""
    name: str      # например, "www.bob.com"
    rtype: str     # "A", "DNSKEY", "RRSIG" и т.д.
    data: str      # IP-адрес или ключ (в демо)

class RRSET:
    """Набор записей с одинаковым именем и типом."""
    def __init__(self, name: str, rtype: str, records: List[ResourceRecord]):
        self.name = name
        self.rtype = rtype
        self.records = records

    def canonical_repr(self) -> bytes:
        """
        Каноническое представление RRSET для хеширования (как в DNSSEC).
        В реальности порядок строгий, здесь – упрощённая склейка.
        """
        items = [f"{r.name}|{r.rtype}|{r.data}" for r in sorted(self.records, key = lambda x: x.data)]
        return "\n".join(items).encode("utf-8")

# ------------------------- Криптографические утилиты (RSA) -------------------------

def generate_zone_keys():
    """Генерирует пару ключей для зоны (например, bob.com)."""
    private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
    public_key = private_key.public_key()
    return private_key, public_key

def public_key_to_dnskey(public_key, key_id: str) -> ResourceRecord:
    """Упаковываем публичный ключ в запись DNSKEY (упрощённо)."""
    # Сериализуем публичный ключ в PEM (в реальности - в специфичный DNSKEY формат)
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return ResourceRecord(name = "bob.com", rtype = "DNSKEY", data = f"{key_id}:{pem.decode()}")

def sign_rrset(rrset: RRSET, private_key, zone_name: str, validity_seconds: int = 3600) -> bytes:
    """
    Подписывает RRSET закрытым ключом зоны.
    Возвращает подпись (RRSIG raw data).
    """
    data_to_sign = rrset.canonical_repr()
    signature = private_key.sign(
        data_to_sign,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature

def verify_rrset(rrset: RRSET, signature: bytes, public_key) -> bool:
    """Проверяет подпись RRSET с помощью открытого ключа зоны."""
    data_to_verify = rrset.canonical_repr()
    try:
        public_key.verify(
            signature,
            data_to_verify,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ------------------------- Симуляция DNS и DNSSEC -------------------------

class DNSSECZone:
    """Зона с поддержкой DNSSEC (аналог bob.com)."""
    def __init__(self, name: str):
        self.name = name
        self.private_key, self.public_key = generate_zone_keys()
        self.records: List[ResourceRecord] = []
        self.rrsigs: dict[str, bytes] = {}  # key: (name|rtype) -> signature

    def add_record(self, name: str, rtype: str, data: str):
        rr = ResourceRecord(name, rtype, data)
        self.records.append(rr)

    def sign_zone(self):
        """Подписываем каждый RRSET в зоне (как в тексте: предварительное подписание)."""
        # Группируем по (name, rtype)
        groups = {}
        for rr in self.records:
            key = (rr.name, rr.rtype)
            if key not in groups:
                groups[key] = []
            groups[key].append(rr)

        for (name, rtype), recs in groups.items():
            rrset = RRSET(name, rtype, recs)
            sig = sign_rrset(rrset, self.private_key, self.name)
            self.rrsigs[f"{name}|{rtype}"] = sig

    def get_signed_response(self, qname: str, qtype: str) -> tuple[Optional[RRSET], Optional[bytes]]:
        """Возвращает RRSET и его подпись (RRSIG)."""
        matching = [rr for rr in self.records if rr.name == qname and rr.rtype == qtype]
        if not matching:
            return None, None
        rrset = RRSET(qname, qtype, matching)
        sig = self.rrsigs.get(f"{qname}|{qtype}")
        return rrset, sig

# ------------------------- Клиент, проверяющий подписи -------------------------

class DNSSECClient:
    """Клиент (Алиса), который проверяет подписи, начиная с доверенного ключа корня."""
    def __init__(self):
        self.trusted_keys = {}  # zone_name -> public_key

    def trust_zone_key(self, zone_name: str, public_key):
        self.trusted_keys[zone_name] = public_key

    def resolve(self, resolver, qname: str, qtype: str) -> Optional[str]:
        """
        Симуляция защищённого разрешения имени.
        resolver – объект, который умеет возвращать RRSET + подпись и DNSKEY.
        """
        # 1. Запрос к серверу зоны (например, родительской или авторитативной)
        rrset, signature, zone_key = resolver.query(qname, qtype)

        if rrset is None:
            print(f"❌ Запись {qname} не найдена")
            return None

        # 2. Проверка подписи через ключ зоны (например, для bob.com проверяем ключом от com)
        zone_name = rrset.name.split('.')[-2] + '.' + rrset.name.split('.')[-1]  # упрощённо
        if zone_name not in self.trusted_keys:
            print(f"⚠️ Нет доверенного ключа для зоны {zone_name}, невозможно проверить")
            return None

        public_key = self.trusted_keys[zone_name]
        if not verify_rrset(rrset, signature, public_key):
            print("🛑 **ПРОВАЛ ВЕРИФИКАЦИИ**: подпись не совпадает! (возможен спуфинг DNS)")
            return None

        print(f"✅ Подпись RRSET для {qname} корректна")
        # Возвращаем данные (например, IP-адрес)
        for rr in rrset.records:
            if rr.rtype == qtype:
                return rr.data
        return None

# ------------------------- Модель атаки (спуфинг DNS) -------------------------

class EvilResolver:
    """Злой DNS-резолвер (Труди), который подменяет ответ."""
    def __init__(self, real_zone: DNSSECZone, evil_ip: str):
        self.real_zone = real_zone
        self.evil_ip = evil_ip

    def query(self, qname: str, qtype: str):
        # Пытается подсунуть фальшивый RRSET
        real_rrset, real_sig = self.real_zone.get_signed_response(qname, qtype)
        if real_rrset is None:
            return None, None, None

        # Фальсификация: меняем IP на адрес Труди
        fake_records = []
        for rr in real_rrset.records:
            if rr.rtype == "A":
                fake_records.append(ResourceRecord(rr.name, "A", self.evil_ip))
            else:
                fake_records.append(rr)

        fake_rrset = RRSET(real_rrset.name, real_rrset.rtype, fake_records)

        # Подпись оставляем старую (подписанную настоящим Бобом) – она НЕ подойдёт,
        # т.к. данные изменились. Это и есть ловушка.
        fake_signature = real_sig  # пытаемся выдать старую подпись за новую
        zone_key = self.real_zone.public_key
        return fake_rrset, fake_signature, zone_key

# ------------------------- Демонстрация -------------------------

def main():
    print("=== DNSSEC Симуляция: защита от спуфинга DNS ===")

    # 1. Создаём реальную зону Боба
    bob_zone = DNSSECZone("bob.com")
    bob_zone.add_record("www.bob.com", "A", "192.0.2.10")
    bob_zone.add_record("mail.bob.com", "A", "192.0.2.20")
    bob_zone.sign_zone()
    print("📌 Зона bob.com создана, ключи сгенерированы, RRSET подписаны.")

    # 2. Клиент (Алиса) изначально доверяет ключу зоны .com (упрощённо: сразу доверяем ключу bob.com)
    alice = DNSSECClient()
    alice.trust_zone_key("bob.com", bob_zone.public_key)
    print("🔑 Алиса доверяет открытому ключу зоны bob.com (получен от родительской зоны).")

    # 3. Нормальный резолвер (без атаки) – должен работать
    class GoodResolver:
        def __init__(self, zone): self.zone = zone
        def query(self, qname, qtype): return self.zone.get_signed_response(qname, qtype) + (self.zone.public_key,)

    good_res = GoodResolver(bob_zone)
    print("\n--- Сценарий 1: Запрос www.bob.com через честный DNS ---")
    ip = alice.resolve(good_res, "www.bob.com", "A")
    print(f"Результат: IP = {ip}\n")

    # 4. Атака: Труди подменяет DNS-ответ
    evil_res = EvilResolver(bob_zone, "10.0.0.100")
    print("--- Сценарий 2: Атака спуфинга DNS (Труди изменяет IP) ---")
    ip_evil = alice.resolve(evil_res, "www.bob.com", "A")
    print(f"Результат: IP = {ip_evil}")

    # 5. Дополнительно: проверка, что другая запись тоже подписана
    print("\n--- Сценарий 3: Нормальный запрос mail.bob.com ---")
    ip_mail = alice.resolve(good_res, "mail.bob.com", "A")
    print(f"Результат: IP = {ip_mail}")

    # 6. Имитация подписанного запроса для защиты от атак повторного воспроизведения (из текста - Transaction Authentication)
    print("\n--- Доп. демонстрация: аутентификация транзакции (подпись хеша запроса) ---")
    query_hash = hashlib.sha256(b"www.bob.com|A|nonce123").digest()
    signed_hash = bob_zone.private_key.sign(query_hash, padding.PKCS1v15(), hashes.SHA256())
    # Клиент проверяет
    bob_zone.public_key.verify(signed_hash, query_hash, padding.PKCS1v15(), hashes.SHA256())
    print("✅ Подпись запроса подтверждена — сервер настоящий.")

if __name__ == "__main__":
    main()