#!/usr/bin/env python3
"""
Программа для демонстрации стандарта X.509 v3 на основе текста:
- Создание самоподписанного сертификата
- Работа с X.500 именем (страна, организация, отдел, общее имя)
- Использование Subject Alternative Name (SAN) для DNS и email
- Проверка принадлежности сертификата указанному DNS
- Отображение структуры сертификата
"""

import datetime
from typing import List, Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


def create_self_signed_certificate(
    country: str = "US",
    state: Optional[str] = None,
    locality: Optional[str] = None,
    organization: str = "MoneyBank",
    organizational_unit: str = "Loan",
    common_name: str = "Bob",
    email_address: Optional[str] = "bob@moneybank.com",
    dns_names: Optional[List[str]] = None,
    valid_days: int = 365,
    key_size: int = 2048,
) -> tuple:
    """
    Создаёт самоподписанный сертификат X.509 версии 3.
    
    Аналог сертификата из примера в тексте:
    /C=US/O=MoneyBank/OU=Loan/CN=Bob/
    
    С третьей версии X.509 добавляем расширение Subject Alternative Name (SAN),
    что позволяет использовать DNS имена вместо (или вместе с) X.500.
    """
    
    # Генерация закрытого ключа
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = key_size,
        backend = default_backend()
    )
    
    # Формируем список атрибутов для X.500 имени (Distinguished Name)
    # Это традиционный способ именования из OSI, который критикуется в тексте
    name_attributes = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]
    
    # Добавляем необязательные поля, если указаны
    if state:
        name_attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        name_attributes.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))
    if email_address:
        name_attributes.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_address))
    
    # Создаём X.500 имя субъекта и издателя (для самоподписанного они совпадают)
    subject = issuer = x509.Name(name_attributes)
    
    # Сейчас создаём сертификат
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    
    # Срок действия
    now = datetime.datetime.utcnow()
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days = valid_days))
    
    # --- КЛЮЧЕВОЕ УЛУЧШЕНИЕ X.509 V3: Subject Alternative Name ---
    # Именно это позволяет "забыть о проблеме" с X.500 именами
    # и привязать сертификат к реальному DNS (bob@moneybank.com → bob.moneybank.com)
    san_entries = []
    
    if dns_names:
        for dns in dns_names:
            san_entries.append(x509.DNSName(dns))
    
    # Добавляем email как SAN (RFC 5280 разрешает)
    if email_address:
        san_entries.append(x509.RFC822Name(email_address))
    
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical = False,  # В данном случае не критично, чтобы сохранить совместимость
        )
    
    # Добавляем базовые ограничения (Basic Constraints) — для CA или конечного сертификата
    builder = builder.add_extension(
        x509.BasicConstraints(ca = False, path_length = None),
        critical = True,
    )
    
    # Добавляем Key Usage (для чего можно использовать ключ)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature = True,
            content_commitment = False,
            key_encipherment = True,
            data_encipherment = False,
            key_agreement = False,
            key_cert_sign = False,
            crl_sign = False,
            encipher_only = False,
            decipher_only = False,
        ),
        critical = True,
    )
    
    # Добавляем Extended Key Usage (для сервера/клиента)
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH,
        ]),
        critical = False,
    )
    
    # Подписываем сертификат
    certificate = builder.sign(
        private_key = private_key,
        algorithm = hashes.SHA256(),
        backend = default_backend()
    )
    
    return certificate, private_key


def print_certificate_details(cert: x509.Certificate) -> None:
    """
    Выводит содержимое сертификата в человеко-читаемом виде,
    иллюстрируя структуру X.509 v3.
    """
    print("=" * 60)
    print("СЕРТИФИКАТ X.509 (версия {})".format(cert.version.value))
    print("=" * 60)
    
    # X.500 имя субъекта — именно то, что критикуется в тексте
    print("\n--- X.500 Distinguished Name (Subject) ---")
    for attribute in cert.subject:
        print(f"  {attribute.oid._name}: {attribute.value}")
    
    print("\n--- Издатель (Issuer) ---")
    for attribute in cert.issuer:
        print(f"  {attribute.oid._name}: {attribute.value}")
    
    print(f"\n--- Срок действия ---")
    print(f"  Действителен с: {cert.not_valid_before}")
    print(f"  Действителен до: {cert.not_valid_after}")
    
    print(f"\n--- Серийный номер ---")
    print(f"  {hex(cert.serial_number)}")
    
    # Расширения (особенно важно — SAN)
    print("\n--- Расширения (X.509 v3) ---")
    for ext in cert.extensions:
        print(f"\n  Расширение: {ext.oid._name}")
        print(f"    Критическое: {ext.critical}")
        # Обработка разных типов расширений для красивого вывода
        if ext.oid._name == "subjectAltName":
            san_values = []
            for name in ext.value:
                san_values.append(f"{type(name).__name__}: {name.value}")
            print(f"    Значение: {', '.join(san_values)}")
        else:
            print(f"    Значение: {ext.value}")
    
    # Отдельно выделим Subject Alternative Name (о нём говорит текст)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        print("\n*** Subject Alternative Name (SAN) — решение проблемы с X.500 ***")
        for name in san.value:
            print(f"    Альтернативное имя: {name.value}")
    except x509.ExtensionNotFound:
        print("\n  (Расширение Subject Alternative Name отсутствует)")
    
    print("\n" + "=" * 60)


def verify_certificate_for_dns(cert: x509.Certificate, dns_name: str) -> bool:
    """
    Проверяет, подходит ли сертификат для указанного DNS-имени.
    Сначала смотрит в SAN (как требует RFC 5280), затем в CN (Common Name).
    Это та самая проверка, которую делает браузер.
    """
    # Современный способ: сначала проверить SAN
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san.value:
            if isinstance(name, x509.DNSName) and name.value == dns_name:
                return True
    except x509.ExtensionNotFound:
        pass
    
    # Устаревший fallback: проверить Common Name в X.500 имени
    # (не рекомендуется, но всё ещё встречается)
    cn_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cn_attributes and cn_attributes[0].value == dns_name:
        print("  Предупреждение: проверка по CN, но правильно использовать SAN")
        return True
    
    return False


def save_cert_and_key(cert: x509.Certificate, private_key: rsa.RSAPrivateKey, cert_path: str = "certificate.pem", key_path: str = "private_key.pem") -> None:
    """Сохраняет сертификат и ключ в PEM-формате."""
    # Сохраняем сертификат
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))
    
    # Сохраняем приватный ключ (без пароля, для демонстрации)
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    print(f"\nСертификат сохранён в {cert_path}")
    print(f"Приватный ключ сохранён в {key_path}")


def load_certificate_from_file(cert_path: str = "certificate.pem") -> Optional[x509.Certificate]:
    """Загружает сертификат из PEM-файла."""
    try:
        with open(cert_path, "rb") as f:
            cert_data = f.read()
        cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        print(f"Сертификат загружен из {cert_path}")
        return cert
    except FileNotFoundError:
        print(f"Файл {cert_path} не найден")
        return None
    except Exception as e:
        print(f"Ошибка загрузки сертификата: {e}")
        return None


def main():
    """Демонстрация работы X.509 сертификата."""
    
    print("Демонстрация X.509 v3 на основе текста\n")
    
    # Создаём сертификат Боба из примера
    # В тексте указан X.500 адрес: /C=US/O=MoneyBank/OU=Loan/CN=Bob
    # И email: bob@moneybank.com
    # Добавляем DNS имя для SAN, чтобы устранить проблему с X.500
    cert, key = create_self_signed_certificate(
        country = "US",
        organization = "MoneyBank",
        organizational_unit = "Loan",
        common_name = "Bob",
        email_address = "bob@moneybank.com",
        dns_names = ["bob.moneybank.com", "www.bob.moneybank.com"],
        valid_days = 365
    )
    
    # Выводим содержимое сертификата
    print_certificate_details(cert)
    
    # Проверяем, что Алиса может идентифицировать Боба по DNS-имени
    # (Это отвечает на вопрос из текста: "не очевидно, что этот сертификат 
    # относится именно к тому Бобу, который ей нужен")
    print("\n--- ПРОВЕРКА ИДЕНТИЧНОСТИ (Алиса проверяет Боба) ---")
    
    test_names = ["bob.moneybank.com", "alice.moneybank.com", "bob@moneybank.com"]
    for name in test_names:
        # Для email проверка чуть сложнее, но принцип тот же
        if "@" in name:
            # Упрощённо: смотрим, есть ли такой email в SAN
            try:
                san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                match = any(isinstance(n, x509.RFC822Name) and n.value == name for n in san.value)
                print(f"  Email '{name}': {'✅ ПОДХОДИТ' if match else '❌ НЕ ПОДХОДИТ'}")
            except x509.ExtensionNotFound:
                print(f"  Email '{name}': ❌ НЕТ SAN РАСШИРЕНИЯ")
        else:
            match = verify_certificate_for_dns(cert, name)
            print(f"  DNS '{name}': {'✅ ПОДХОДИТ' if match else '❌ НЕ ПОДХОДИТ'}")
    
    # Сохраняем для возможного использования в реальных приложениях
    save_cert_and_key(cert, key)
    
    print("\n=== ВЫВОД ===")
    print("1. Сертификат имеет X.500 имя: /C=US/O=MoneyBank/OU=Loan/CN=Bob")
    print("2. Благодаря X.509 v3 добавлено расширение Subject Alternative Name (SAN)")
    print("3. SAN содержит DNS и email, что позволяет однозначно идентифицировать")
    print("   Боба в интернете, решая проблему, описанную в тексте.")
    print("4. Это именно то, что используют HTTPS-сайты каждый день.")


if __name__ == "__main__":
    main()