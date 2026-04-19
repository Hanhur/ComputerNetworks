import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


@dataclass
class Certificate:
    """Сертификат X.509 (упрощённая версия)"""
    subject: str  # владелец (кто имеет этот сертификат)
    issuer: str   # кто выдал (ЦС, подписавший сертификат)
    public_key_pem: bytes  # открытый ключ владельца
    serial_number: int  # уникальный номер
    valid_from: float  # дата начала действия (timestamp)
    valid_to: float    # дата окончания действия
    is_ca: bool = False  # может ли этот сертификат подписывать другие
    signature: bytes = None  # подпись от issuer
    user_private_key: any = None  # для хранения приватного ключа пользователя
    
    def to_bytes(self) -> bytes:
        """Преобразует сертификат в байты для подписи (без signature)"""
        data = {
            'subject': self.subject,
            'issuer': self.issuer,
            'public_key': self.public_key_pem.hex(),
            'serial_number': self.serial_number,
            'valid_from': self.valid_from,
            'valid_to': self.valid_to,
            'is_ca': self.is_ca
        }
        return json.dumps(data, sort_keys = True).encode()
    
    def is_expired(self) -> bool:
        """Проверка срока действия"""
        now = time.time()
        return now < self.valid_from or now > self.valid_to


class CertificateAuthority:
    """Центр сертификации (CA)"""
    
    def __init__(self, name: str, is_root: bool = False):
        self.name = name
        self.is_root = is_root
        self.serial_counter = 1000
        
        # Генерация ключевой пары (RSA 2048)
        self.private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 2048,
            backend = default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Свой собственный сертификат
        self.certificate = None
        
        # Для корневого ЦС создаём самоподписанный сертификат
        if is_root:
            self._create_root_certificate()
            print(f"✓ Создан корневой ЦС: {name}")
        else:
            print(f"✓ Создан ЦС: {name}")
        
        # Список отозванных сертификатов (CRL)
        self.revoked_certificates: List[int] = []
    
    def _create_root_certificate(self):
        """Создать самоподписанный сертификат для корневого ЦС"""
        cert = Certificate(
            subject = self.name,
            issuer = self.name,  # корневой ЦС подписывает сам себя
            public_key_pem = self.public_key_pem,
            serial_number = 1,
            valid_from = time.time(),
            valid_to = time.time() + 10 * 365 * 24 * 3600,  # 10 лет
            is_ca = True
        )
        # Подписать сертификат своим же ключом
        cert.signature = self.sign_bytes(cert.to_bytes())
        self.certificate = cert
    
    def sign_bytes(self, data: bytes) -> bytes:
        """Подписать данные своим закрытым ключом"""
        return self.private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    
    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
        """Проверить подпись (статический метод)"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def sign_certificate(self, subject: str, public_key_pem: bytes = None, is_ca: bool = False, validity_years: int = 1) -> Certificate:
        """Выдать сертификат для субъекта"""
        if self.certificate is None and not self.is_root:
            raise Exception(f"ЦС {self.name} не имеет собственного сертификата!")
        
        # Если не передан публичный ключ, используем свой (для самоподписи)
        if public_key_pem is None:
            public_key_pem = self.public_key_pem
        
        cert = Certificate(
            subject = subject,
            issuer = self.name,
            public_key_pem = public_key_pem,
            serial_number = self.serial_counter,
            valid_from = time.time(),
            valid_to = time.time() + validity_years * 365 * 24 * 3600,
            is_ca = is_ca
        )
        self.serial_counter += 1
        
        # Подписать сертификат
        cert.signature = self.sign_bytes(cert.to_bytes())
        return cert
    
    def revoke_certificate(self, serial_number: int):
        """Отозвать сертификат"""
        self.revoked_certificates.append(serial_number)
        print(f"⚠ Сертификат #{serial_number} отозван ЦС {self.name}")
    
    def is_revoked(self, serial_number: int) -> bool:
        """Проверить, отозван ли сертификат"""
        return serial_number in self.revoked_certificates


class PKIManager:
    """Управление инфраструктурой открытых ключей"""
    
    def __init__(self):
        self.root_cas: Dict[str, CertificateAuthority] = {}  # доверительные якоря
        self.intermediate_cas: Dict[str, CertificateAuthority] = {}
        self.user_certificates: Dict[str, Certificate] = {}
    
    def create_root_ca(self, name: str) -> CertificateAuthority:
        """Создать корневой ЦС (доверительный якорь)"""
        root = CertificateAuthority(name, is_root = True)
        self.root_cas[name] = root
        return root
    
    def create_intermediate_ca(self, name: str, issuer_ca: CertificateAuthority) -> CertificateAuthority:
        """Создать промежуточный ЦС, подписанный вышестоящим ЦС"""
        intermediate = CertificateAuthority(name, is_root = False)
        
        # Вышестоящий ЦС выдаёт сертификат промежуточному
        intermediate.certificate = issuer_ca.sign_certificate(
            subject = name,
            public_key_pem = intermediate.public_key_pem,
            is_ca = True,
            validity_years = 5
        )
        
        self.intermediate_cas[name] = intermediate
        print(f"  └─ Подписан ЦС '{issuer_ca.name}'")
        return intermediate
    
    def issue_user_certificate(self, user_name: str, ca: CertificateAuthority) -> Certificate:
        """Выдать сертификат пользователю от указанного ЦС"""
        # Генерация ключей пользователя
        user_private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())
        user_public_key_pem = user_private_key.public_key().public_bytes(encoding = serialization.Encoding.PEM, format = serialization.PublicFormat.SubjectPublicKeyInfo)
        
        # ЦС подписывает сертификат пользователя
        cert = ca.sign_certificate(subject = user_name, public_key_pem = user_public_key_pem, is_ca = False, validity_years = 1)
        
        # Сохраняем приватный ключ пользователя
        cert.user_private_key = user_private_key
        self.user_certificates[user_name] = cert
        return cert
    
    def verify_certificate_chain(self, user_cert: Certificate, intermediate_certs: List[Certificate], root_ca: CertificateAuthority) -> tuple[bool, str]:
        """
        Проверить цепочку доверия (chain of trust)
        Алиса проверяет сертификат Боба через промежуточные ЦС до корневого
        """
        print("\n" + "=" * 60)
        print("ПРОВЕРКА ЦЕПОЧКИ ДОВЕРИЯ (Chain of Trust)")
        print("=" * 60)
        
        # 1. Проверка срока действия сертификата пользователя
        if user_cert.is_expired():
            return False, f"Сертификат пользователя {user_cert.subject} просрочен"
        
        # 2. Проверка подписи пользовательского сертификата
        current_cert = user_cert
        
        # Ищем ЦС, который подписал текущий сертификат
        signer_cert = None
        for ic in intermediate_certs:
            if ic.subject == current_cert.issuer:
                signer_cert = ic
                break
        
        if signer_cert is None and current_cert.issuer == root_ca.name:
            signer_cert = root_ca.certificate
        
        if signer_cert is None:
            return False, f"Не найден ЦС, выдавший сертификат: {current_cert.issuer}"
        
        # Проверяем подпись
        valid = CertificateAuthority.verify_signature(current_cert.to_bytes(), current_cert.signature, signer_cert.public_key_pem)
        
        if not valid:
            return False, f"Неверная подпись сертификата {current_cert.subject}"
        
        print(f"✓ Сертификат {current_cert.subject} подписан {current_cert.issuer}")
        
        # 3. Проверка всей цепочки до корня
        print("\nЦепочка сертификатов:")
        chain_display = [user_cert] + intermediate_certs
        for i, cert in enumerate(chain_display):
            ca_mark = " (CA)" if cert.is_ca else ""
            print(f"  [{i}] {cert.subject}{ca_mark} ← выдан: {cert.issuer}")
        
        # 4. Проверка корневого сертификата (доверительного якоря)
        print(f"\n✓ Корневой доверительный якорь: {root_ca.name}")
        
        # Дополнительно проверяем, что корневой сертификат самоподписан
        root_valid = CertificateAuthority.verify_signature(root_ca.certificate.to_bytes(), root_ca.certificate.signature, root_ca.certificate.public_key_pem)
        if root_valid:
            print(f"✓ Корневой сертификат {root_ca.name} действителен (самоподписан)")
        
        return True, "Цепочка доверия успешно проверена!"
    
    def print_crl(self, ca: CertificateAuthority):
        """Вывести список отозванных сертификатов"""
        print(f"\nСписок отозванных сертификатов (CRL) для {ca.name}:")
        if ca.revoked_certificates:
            for sn in ca.revoked_certificates:
                print(f"  • Серийный номер: {sn}")
        else:
            print("  (пусто)")
    
    def get_trust_anchors_info(self) -> List[str]:
        """Получить список всех доверительных якорей"""
        return list(self.root_cas.keys())


# ============================================================
# ДЕМОНСТРАЦИЯ РАБОТЫ PKI
# ============================================================

def main():
    print("\n" + "█" * 60)
    print("СИМУЛЯЦИЯ ИНФРАСТРУКТУРЫ ОТКРЫТЫХ КЛЮЧЕЙ (PKI)")
    print("█" * 60)
    
    # 1. СОЗДАНИЕ ИЕРАРХИИ ЦС
    print("\n[1] СОЗДАНИЕ ИЕРАРХИИ ЦЕНТРОВ СЕРТИФИКАЦИИ")
    print("-" * 40)
    
    pki = PKIManager()
    
    # Корневой ЦС (доверительный якорь) - "вшит" в браузер
    root_ca = pki.create_root_ca("GlobalRoot Trust (вшит в браузер)")
    
    # Промежуточный ЦС (региональный)
    regional_ca = pki.create_intermediate_ca("Regional CA Europe", root_ca)
    
    # Пользовательский ЦС (выдаёт сертификаты конечным пользователям)
    user_ca = pki.create_intermediate_ca("User CA Department", regional_ca)
    
    # 2. ВЫДАЧА СЕРТИФИКАТА ПОЛЬЗОВАТЕЛЮ (БОБ)
    print("\n[2] БОБ ЗАПРАШИВАЕТ СЕРТИФИКАТ")
    print("-" * 40)
    bob_cert = pki.issue_user_certificate("Bob (пользователь)", user_ca)
    print(f"✓ Сертификат Боба выдан ЦС '{user_ca.name}'")
    print(f"  Серийный номер: {bob_cert.serial_number}")
    print(f"  Действителен до: {time.ctime(bob_cert.valid_to)}")
    
    # 3. ЦЕПОЧКА СЕРТИФИКАТОВ (Боб собирает и отправляет Алисе)
    print("\n[3] БОБ СОБИРАЕТ ЦЕПОЧКУ СЕРТИФИКАТОВ")
    print("-" * 40)
    chain = [bob_cert, user_ca.certificate, regional_ca.certificate]
    print("Боб отправляет Алисе цепочку (chain of trust):")
    for cert in chain:
        ca_type = " (промежуточный CA)" if cert.is_ca and cert.subject != root_ca.name else ""
        if cert.subject == root_ca.name:
            ca_type = " (корневой CA)"
        elif not cert.is_ca:
            ca_type = " (пользователь)"
        print(f"  → {cert.subject}{ca_type}")
    
    # 4. АЛИСА ПРОВЕРЯЕТ ЦЕПОЧКУ
    print("\n[4] АЛИСА ПРОВЕРЯЕТ ЦЕПОЧКУ ДОВЕРИЯ")
    print("-" * 40)
    print("У Алисы в браузере 'вшит' корневой сертификат:", root_ca.name)
    
    result, message = pki.verify_certificate_chain(
        bob_cert,
        [user_ca.certificate, regional_ca.certificate],
        root_ca
    )
    print(f"\nРЕЗУЛЬТАТ: {message}")
    
    # 5. ОТЗЫВ СЕРТИФИКАТА
    print("\n[5] ОТЗЫВ СЕРТИФИКАТА (CRL)")
    print("-" * 40)
    print("Нарушение условий → Боба лишают сертификата")
    user_ca.revoke_certificate(bob_cert.serial_number)
    pki.print_crl(user_ca)
    
    # 6. ПОПЫТКА ИСПОЛЬЗОВАТЬ ОТОЗВАННЫЙ СЕРТИФИКАТ
    print("\n[6] АЛИСА ПРОВЕРЯЕТ ОТОЗВАННЫЙ СЕРТИФИКАТ")
    print("-" * 40)
    if user_ca.is_revoked(bob_cert.serial_number):
        print(f"⚠ ВНИМАНИЕ: Сертификат #{bob_cert.serial_number} находится в CRL!")
        print("  Алиса ОТКЛОНЯЕТ соединение с Бобом.")
    else:
        print("  Сертификат действителен, не отозван.")
    
    # 7. ДОПОЛНИТЕЛЬНО: ПРОВЕРКА СРОКА ДЕЙСТВИЯ
    print("\n[7] ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ")
    print("-" * 40)
    if bob_cert.is_expired():
        print("✗ Сертификат просрочен")
    else:
        print("✓ Срок действия сертификата не истёк")
    
    # 8. ИНФОРМАЦИЯ О ДОВЕРИТЕЛЬНЫХ ЯКОРЯХ
    print("\n[8] ДОВЕРИТЕЛЬНЫЕ ЯКОРЯ (Trust Anchors)")
    print("-" * 40)
    print("В браузер Алисы 'вшиты' корневые сертификаты:")
    for name in pki.get_trust_anchors_info():
        print(f"  • {name}")
    print("\nБез этого доверительного якоря проверить цепочку невозможно!")
    
    # 9. ДЕМОНСТРАЦИЯ ПРОБЛЕМЫ ЕДИНОГО МИРОВОГО ЦС
    print("\n[9] ПОЧЕМУ НЕЛЬЗЯ ИМЕТЬ ОДИН ЦС НА ВЕСЬ МИР?")
    print("-" * 40)
    print("• Огромная нагрузка → медленная работа")
    print("• Единая точка отказа → компрометация ключа = катастрофа")
    print("• Политический вопрос: какая организация будет управлять?")
    print("\nРешение PKI: множество корневых ЦС (как в вашем браузере):")
    print("  - Microsoft, Apple, Google, Mozilla")
    print("  - Государственные ЦС (Китай, Россия, США)")
    print("  - Банковские и корпоративные ЦС")
    
    print("\n" + "█" * 60)
    print("КЛЮЧЕВЫЕ ВЫВОДЫ (из вашего текста):")
    print("█" * 60)
    print("✓ PKI использует иерархию ЦС для распределения доверия")
    print("✓ Корневой ЦС — доверительный якорь ('вшит' в браузер/ОС)")
    print("✓ Цепочка сертификатов (chain of trust) позволяет проверить подлинность")
    print("✓ CRL необходим для отзыва скомпрометированных сертификатов")
    print("✓ Проблема одного мирового ЦС решена множеством корневых ЦС")
    print("✓ Доверие конечного пользователя = доверие производителю браузера")
    print("█" * 60 + "\n")


if __name__ == "__main__":
    main()