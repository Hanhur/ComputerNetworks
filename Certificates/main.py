import hashlib
import json
import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ------------------- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ -------------------
def generate_key_pair():
    """Генерирует пару (приватный ключ, публичный ключ) RSA"""
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    """Сериализует публичный ключ в байты для хранения в сертификате"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_bytes):
    """Десериализует публичный ключ из байтов"""
    return serialization.load_pem_public_key(pem_bytes, backend = default_backend())

def compute_hash(data):
    """Вычисляет SHA-2 хеш (SHA-256) от данных"""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# ------------------- ЦЕНТР СЕРТИФИКАЦИИ (CA) -------------------
class CertificateAuthority:
    def __init__(self, name = "MyCA"):
        self.name = name
        self.private_key, self.public_key = generate_key_pair()
        print(f"[CA] Создан центр сертификации: {self.name}")

    def issue_certificate(self, subject_name, subject_public_key, attributes = None):
        """
        Выпускает сертификат для субъекта.
        Сертификат - это JSON с данными, подписанный закрытым ключом CA.
        """
        cert_data = {
            "subject": subject_name,
            "public_key_pem": serialize_public_key(subject_public_key).decode('utf-8'),
            "attributes": attributes if attributes else {},
            "ca_name": self.name
        }
        # Преобразуем в строку для хеширования
        cert_str = json.dumps(cert_data, sort_keys = True)
        cert_hash = compute_hash(cert_str)
        # Подписываем хеш закрытым ключом CA
        signature = self.private_key.sign(
            cert_hash.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print(f"[CA] Выдан сертификат для {subject_name} (атрибуты: {attributes})")
        return cert_data, signature

    def verify_certificate(self, cert_data, signature, ca_public_key = None):
        """Проверяет подлинность сертификата с использованием открытого ключа CA"""
        if ca_public_key is None:
            ca_public_key = self.public_key

        cert_str = json.dumps(cert_data, sort_keys = True)
        cert_hash = compute_hash(cert_str)
        try:
            ca_public_key.verify(
                signature,
                cert_hash.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("[CA] Подпись сертификата ВЕРНА.")
            return True
        except Exception:
            print("[CA] Подпись сертификата НЕВЕРНА! Возможна подмена.")
            return False

# ------------------- ПОЛЬЗОВАТЕЛИ (Боб, Алиса, Труди) -------------------
class User:
    def __init__(self, name):
        self.name = name
        self.private_key, self.public_key = generate_key_pair()
        self.certificate = None
        self.certificate_signature = None

    def request_certificate(self, ca, attributes = None):
        """Запрашивает сертификат у CA"""
        self.certificate, self.certificate_signature = ca.issue_certificate(
            self.name, self.public_key, attributes
        )
        print(f"[{self.name}] Получил сертификат от {ca.name}")

    def publish_certificate(self):
        """Публикует сертификат (например, на сайте)"""
        print(f"\n[{self.name}] Публикую сертификат на своей странице:")
        print(json.dumps(self.certificate, indent = 2))

    def get_public_key_from_certificate(self, cert_data):
        """Извлекает публичный ключ из сертификата"""
        pem_bytes = cert_data["public_key_pem"].encode('utf-8')
        return deserialize_public_key(pem_bytes)

    def verify_peer(self, peer_cert_data, peer_signature, ca_public_key):
        """Проверяет подлинность сертификата собеседника"""
        print(f"\n[{self.name}] Проверяю сертификат {peer_cert_data['subject']}...")
        is_valid = ca.verify_certificate(peer_cert_data, peer_signature, ca_public_key)
        if is_valid:
            print(f"[{self.name}] Сертификат {peer_cert_data['subject']} действителен.")
        else:
            print(f"[{self.name}] ВНИМАНИЕ! Сертификат {peer_cert_data['subject']} ПОДДЕЛАН!")
        return is_valid

    def encrypt_message(self, public_key_recipient, message):
        """Шифрует сообщение открытым ключом получателя"""
        ciphertext = public_key_recipient.encrypt(
            message.encode('utf-8'),
            padding.PKCS1v15()
        )
        return ciphertext

    def decrypt_message(self, ciphertext):
        """Расшифровывает сообщение своим закрытым ключом"""
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.PKCS1v15()
        )
        return plaintext.decode('utf-8')

# ------------------- АТАКА ТРУДИ -------------------
def trudy_attack(user_bob, alice, ca_public_key):
    """
    Труди перехватывает запрос и пытается подменить открытый ключ.
    """
    print("\n" + "=" * 60)
    print("СЦЕНАРИЙ: ТРУДИ ПЫТАЕТСЯ ПОДМЕНИТЬ СЕРТИФИКАТ")
    print("=" * 60)

    # Труди создаёт свой фальшивый сертификат с именем Боба
    trudy = User("Trudy")
    fake_cert_data = {
        "subject": "Bob",  # <- имя Боба!
        "public_key_pem": serialize_public_key(trudy.public_key).decode('utf-8'),
        "attributes": {},
        "ca_name": "MyCA"
    }
    # Но подписи у Труди нет! Она не знает закрытый ключ CA.
    fake_signature = b"fake_signature_from_trudy"

    print("[Труди] Я перехватила запрос и подменила сертификат Боба на свой!")
    print("[Труди] В сертификате указано имя 'Bob', но ключ принадлежит мне.")

    # Алиса проверяет подделку
    is_valid = alice.verify_peer(fake_cert_data, fake_signature, ca_public_key)
    if not is_valid:
        print("[Алиса] ОБНАРУЖЕНА АТАКА! Не доверяю этому ключу.")

# ------------------- АТРИБУТНЫЙ СЕРТИФИКАТ (ВОЗРАСТ 18+) -------------------
def age_verification_demo(ca):
    """
    Демонстрация сертификата с атрибутом "старше 18 лет".
    """
    print("\n" + "=" * 60)
    print("СЦЕНАРИЙ: СЕРТИФИКАТ С ВОЗРАСТНЫМ АТРИБУТОМ")
    print("=" * 60)

    user = User("Анонимный_клиент")
    user.request_certificate(ca, attributes = {"age_over_18": True})

    # Сайт, который проверяет возраст
    website_private, website_public = generate_key_pair()

    # Сайт генерирует случайное число
    nonce = random.randint(100000, 999999)
    print(f"[Сайт] Генерирую случайное число: {nonce}")

    # Шифруем случайное число открытым ключом из сертификата клиента
    client_pubkey = user.get_public_key_from_certificate(user.certificate)
    encrypted_nonce = user.encrypt_message(client_pubkey, str(nonce))

    # Клиент расшифровывает своим закрытым ключом
    decrypted_nonce = user.decrypt_message(encrypted_nonce)
    print(f"[Клиент] Расшифровал число: {decrypted_nonce}")

    if int(decrypted_nonce) == nonce:
        print("[Сайт] Клиент подтвердил владение закрытым ключом.")
        print("[Сайт] Возрастной атрибут сертификата:", user.certificate['attributes'].get('age_over_18', False))
        print("[Сайт] ДОСТУП РАЗРЕШЁН (подтверждён возраст 18+).")
    else:
        print("[Сайт] ДОСТУП ЗАПРЕЩЁН.")

# ------------------- ГЛАВНАЯ ФУНКЦИЯ -------------------
if __name__ == "__main__":
    # 1. Создаём CA
    ca = CertificateAuthority("TrustedCA")

    # 2. Боб получает сертификат
    bob = User("Bob")
    bob.request_certificate(ca)

    # 3. Алиса хочет связаться с Бобом
    alice = User("Alice")

    print("\n" + "=" * 60)
    print("НОРМАЛЬНЫЙ СЦЕНАРИЙ: АЛИСА ПРОВЕРЯЕТ СЕРТИФИКАТ БОБА")
    print("=" * 60)

    # Алиса скачивает сертификат Боба (например, с его сайта)
    bob.publish_certificate()

    # Алиса проверяет подлинность сертификата Боба
    is_valid = alice.verify_peer(bob.certificate, bob.certificate_signature, ca.public_key)

    if is_valid:
        print(f"[Алиса] Успешно проверила сертификат Боба. Могу безопасно общаться.")
        # Дополнительно: Алиса извлекает публичный ключ Боба
        bob_public = alice.get_public_key_from_certificate(bob.certificate)
        print(f"[Алиса] Публичный ключ Боба извлечён и подтверждён CA.")
    else:
        print("[Алиса] Что-то не так с сертификатом!")

    # 4. Атака Труди
    trudy_attack(bob, alice, ca.public_key)

    # 5. Демонстрация атрибутного сертификата (возраст)
    age_verification_demo(ca)