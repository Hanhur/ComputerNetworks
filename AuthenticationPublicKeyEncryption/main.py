import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# ========== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ==========
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(pub_key):
    return pub_key.public_bytes(
        encoding = serialization.Encoding.PEM,
        format = serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data, backend = default_backend())

def rsa_encrypt(public_key, plaintext: bytes) -> bytes:
    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf = padding.MGF1(algorithm = hashes.SHA256()),
            algorithm = hashes.SHA256(),
            label = None
        )
    )

def generate_nonce() -> int:
    return random.randint(1, 10 ** 12)

def generate_session_key() -> bytes:
    return random.randbytes(32)  # 256-bit session key

# ========== МОДЕЛЬ ПРОТОКОЛА ==========
class DirectoryServer:
    """Сервер каталогов, выдающий сертификаты (упрощённо: просто хранит публичные ключи)"""
    def __init__(self):
        self.db = {}  # name -> public_key (PEM)

    def register(self, name, public_key_pem):
        self.db[name] = public_key_pem

    def get_public_key(self, name):
        if name in self.db:
            return self.db[name]
        else:
            raise ValueError(f"No public key found for {name}")

class Alice:
    def __init__(self, name, directory, bob_name):
        self.name = name
        self.private_key, self.public_key = generate_rsa_keypair()
        self.directory = directory
        self.bob_name = bob_name
        self.bob_public_key = None
        self.my_nonce = None
        self.session_key = None

    def step1_request_bob_cert(self):
        print(f"[{self.name}] -> Сообщение 1: Запрос сертификата Боба")
        # реально тут был бы запрос к серверу каталогов
        return

    def step2_receive_bob_cert(self):
        bob_pem = self.directory.get_public_key(self.bob_name)
        self.bob_public_key = deserialize_public_key(bob_pem)
        print(f"[{self.name}] -> Сообщение 2: Получен сертификат Боба (публичный ключ)")

    def step3_send_id_and_nonce(self):
        self.my_nonce = generate_nonce()
        message = f"{self.name},{self.my_nonce}".encode('utf-8')
        encrypted = rsa_encrypt(self.bob_public_key, message)
        print(f"[{self.name}] -> Сообщение 3: (ID_A || R_A) зашифровано публичным ключом Боба")
        return encrypted

    def step6_receive_and_decrypt(self, encrypted_message):
        # сообщение 6 от Боба: зашифровано открытым ключом Алисы, внутри: R_A, R_B, K_s
        decrypted = rsa_decrypt(self.private_key, encrypted_message)
        parts = decrypted.decode('utf-8').split(',')
        if len(parts) != 3:
            raise ValueError("Неверный формат сообщения 6")
        received_RA = int(parts[0])
        received_RB = int(parts[1])
        session_key = bytes.fromhex(parts[2])

        if received_RA == self.my_nonce:
            print(f"[{self.name}] R_A совпадает! Боб аутентифицирован.")
            self.session_key = session_key
            print(f"[{self.name}] Сеансовый ключ K_s получен: {session_key.hex()}")
            return received_RB, session_key
        else:
            raise Exception("Аутентификация Боба не удалась: R_A не совпадает")

    def step7_send_encrypted_RB(self, RB, session_key):
        # в реальности здесь симметричное шифрование, но для простоты покажем шифрование сеансовым ключом (AES нет, используем XOR)
        # для демонстрации – просто зашифруем RB сеансовым ключом как байты
        rb_bytes = str(RB).encode('utf-8')
        # упрощённое шифрование (только для симуляции)
        encrypted_rb = bytes([a ^ b for a, b in zip(rb_bytes, session_key[:len(rb_bytes)])])
        print(f"[{self.name}] -> Сообщение 7: (R_B) зашифровано сеансовым ключом")
        return encrypted_rb

class Bob:
    def __init__(self, name, directory):
        self.name = name
        self.private_key, self.public_key = generate_rsa_keypair()
        self.directory = directory
        self.alice_public_key = None
        self.alice_nonce = None
        self.my_nonce = None
        self.proposed_session_key = None

    def register_with_directory(self):
        pub_pem = serialize_public_key(self.public_key)
        self.directory.register(self.name, pub_pem)

    def step3_receive(self, encrypted_from_alice):
        # расшифровываем своим приватным ключом
        decrypted = rsa_decrypt(self.private_key, encrypted_from_alice)
        parts = decrypted.decode('utf-8').split(',')
        if len(parts) != 2:
            raise ValueError("Неверный формат сообщения 3")
        sender_name = parts[0]
        self.alice_nonce = int(parts[1])
        print(f"[{self.name}] Получено сообщение 3 от {sender_name} с R_A={self.alice_nonce}")
        return sender_name

    def step4_request_alice_cert(self, alice_name):
        print(f"[{self.name}] -> Сообщение 4: Запрос сертификата Алисы")
        alice_pem = self.directory.get_public_key(alice_name)
        self.alice_public_key = deserialize_public_key(alice_pem)
        print(f"[{self.name}] -> Сообщение 5: Получен сертификат Алисы")

    def step6_send_RA_RB_Ks(self):
        self.my_nonce = generate_nonce()
        self.proposed_session_key = generate_session_key()
        # формируем сообщение: R_A, R_B, K_s
        plaintext = f"{self.alice_nonce},{self.my_nonce},{self.proposed_session_key.hex()}"
        encrypted = rsa_encrypt(self.alice_public_key, plaintext.encode('utf-8'))
        print(f"[{self.name}] -> Сообщение 6: (R_A, R_B, K_s) зашифровано публичным ключом Алисы")
        return encrypted

    def step7_receive(self, encrypted_rb, session_key):
        # расшифровываем RB сеансовым ключом
        rb_bytes = str(self.my_nonce).encode('utf-8')
        decrypted_rb_bytes = bytes([a ^ b for a, b in zip(encrypted_rb, session_key[:len(rb_bytes)])])
        try:
            received_RB = int(decrypted_rb_bytes.decode('utf-8'))
            if received_RB == self.my_nonce:
                print(f"[{self.name}] R_B совпадает! Алиса аутентифицирована. Сеанс установлен.")
                return True
            else:
                print(f"[{self.name}] Ошибка: R_B не совпадает")
                return False
        except:
            print(f"[{self.name}] Ошибка расшифровки R_B")
            return False

# ========== ЗАПУСК ПРОТОКОЛА ==========
if __name__ == "__main__":
    # Инициализация
    dir_server = DirectoryServer()
    alice = Alice("Alice", dir_server, "Bob")
    bob = Bob("Bob", dir_server)

    # Регистрация Боба в каталоге
    bob.register_with_directory()
    # Регистрация Алисы (чтобы Боб мог её найти)
    alice_pem = serialize_public_key(alice.public_key)
    dir_server.register("Alice", alice_pem)

    print("\n=== НАЧАЛО ПРОТОКОЛА ===\n")
    # Шаг 1-2: Алиса получает сертификат Боба
    alice.step1_request_bob_cert()
    alice.step2_receive_bob_cert()

    # Шаг 3: Алиса отправляет ID_A и R_A, зашифрованные публичным ключом Боба
    msg3 = alice.step3_send_id_and_nonce()

    # Шаг 3 на стороне Боба: приём и расшифровка
    sender = bob.step3_receive(msg3)

    # Шаг 4-5: Боб запрашивает сертификат Алисы
    bob.step4_request_alice_cert(sender)

    # Шаг 6: Боб отправляет R_A, R_B, K_s, зашифрованные публичным ключом Алисы
    msg6 = bob.step6_send_RA_RB_Ks()

    # Шаг 6 на стороне Алисы: расшифровка и проверка R_A
    RB, session_key = alice.step6_receive_and_decrypt(msg6)

    # Шаг 7: Алиса отправляет R_B, зашифрованный сеансовым ключом
    msg7 = alice.step7_send_encrypted_RB(RB, session_key)

    # Шаг 7 на стороне Боба: проверка R_B
    success = bob.step7_receive(msg7, session_key)

    print("\n=== РЕЗУЛЬТАТ ===")
    if success:
        print("✅ Взаимная аутентификация успешна. Боб и Алиса доверяют друг другу.")
    else:
        print("❌ Аутентификация не удалась.")