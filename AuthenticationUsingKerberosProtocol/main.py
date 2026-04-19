import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ---------------------- Вспомогательные функции ----------------------
def derive_key_from_password(password: str) -> bytes:
    """Имитация получения секретного ключа из пароля (K_Alice, K_Bob, K_TGS)"""
    return hashlib.sha256(password.encode()).digest()[:16]  # 16 байт для AES-128

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-CBC шифрование"""
    iv = secrets.token_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ct

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC дешифрование"""
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

# ---------------------- Структуры данных ----------------------
@dataclass
class Ticket:
    """Билет (удостоверение)"""
    service_name: str      # имя сервера или TGS, для которого билет
    client_name: str       # имя клиента (Алиса)
    session_key: bytes     # сессионный ключ для связи клиента с сервером
    timestamp: float       # временная метка выдачи
    lifetime: float = 300.0 # время жизни (сек)

    def serialize(self) -> bytes:
        """Преобразование билета в байты для шифрования"""
        data = f"{self.service_name}|{self.client_name}|{self.session_key.hex()}|{self.timestamp}|{self.lifetime}"
        return data.encode()

    @staticmethod
    def deserialize(data: bytes):
        """Восстановление билета из байтов"""
        parts = data.decode().split('|')
        return Ticket(
            service_name = parts[0],
            client_name = parts[1],
            session_key = bytes.fromhex(parts[2]),
            timestamp = float(parts[3]),
            lifetime = float(parts[4])
        )

# ---------------------- Стороны протокола ----------------------
class AuthenticationServer:
    """Сервер аутентификации (AS)"""
    def __init__(self):
        self.user_keys: Dict[str, bytes] = {}  # логин -> долговременный ключ

    def register_user(self, username: str, password: str):
        """Регистрация пользователя (только для имитации)"""
        self.user_keys[username] = derive_key_from_password(password)

    def handle_request(self, username: str, tgs_name: str) -> Optional[bytes]:
        """
        Шаг 1-2 протокола:
        AS получает имя пользователя и TGS, возвращает зашифрованное сообщение,
        содержащее сессионный ключ K_Alice_TGS и билет для TGS (зашифрованный ключом TGS)
        """
        if username not in self.user_keys:
            return None
        alice_key = self.user_keys[username]

        # Генерируем сессионный ключ для связи Алисы с TGS
        session_key_alice_tgs = secrets.token_bytes(16)

        # Создаем билет для TGS (будет зашифрован ключом TGS)
        ticket_for_tgs = Ticket(
            service_name = tgs_name,
            client_name = username,
            session_key = session_key_alice_tgs,
            timestamp = time.time()
        )

        # Сообщение 2: (сессионный ключ + билет), зашифрованное ключом Алисы
        # В реальности TGS ключ известен AS, мы его имитируем
        tgs_key = derive_key_from_password("master_key_of_TGS")  # упрощенно
        encrypted_ticket = encrypt(tgs_key, ticket_for_tgs.serialize())

        # Формируем ответ AS: [session_key, encrypted_ticket]
        plain_response = session_key_alice_tgs + b"||" + encrypted_ticket
        encrypted_response = encrypt(alice_key, plain_response)

        return encrypted_response

class TicketGrantingServer:
    """Сервер выдачи удостоверений (TGS)"""
    def __init__(self, name: str):
        self.name = name
        self.secret_key = derive_key_from_password("master_key_of_TGS")
        self.service_keys: Dict[str, bytes] = {}  # имя сервиса -> его долговременный ключ

    def register_service(self, service_name: str, password: str):
        """Регистрация сервера услуг (Боба)"""
        self.service_keys[service_name] = derive_key_from_password(password)

    def handle_request(self, encrypted_ticket: bytes, authenticator: bytes) -> Optional[bytes]:
        """
        Шаг 3-4: TGS получает билет (зашифрованный ключом TGS) и аутентификатор.
        Возвращает сессионный ключ K_Alice_Bob и билет для Боба.
        """
        # Расшифровываем билет
        try:
            ticket_data = decrypt(self.secret_key, encrypted_ticket)
            ticket = Ticket.deserialize(ticket_data)
        except Exception:
            return None  # билет подделан

        # Проверяем время жизни билета
        if time.time() - ticket.timestamp > ticket.lifetime:
            return None  # билет истек

        # Расшифровываем аутентификатор (должен быть зашифрован сессионным ключом из билета)
        try:
            auth_data = decrypt(ticket.session_key, authenticator)
            client_name, client_timestamp = auth_data.decode().split('|')
        except Exception:
            return None

        # Проверяем соответствие имени и временную метку
        if client_name != ticket.client_name or abs(time.time() - float(client_timestamp)) > 5.0:
            return None  # атака повтора или подмена

        # Генерируем новый сессионный ключ для Алисы и Боба
        session_key_alice_bob = secrets.token_bytes(16)

        # Билет для Боба (шифруется ключом Боба)
        bob_key = self.service_keys.get("Bob", None)
        if not bob_key:
            return None

        ticket_for_bob = Ticket(
            service_name="Bob",
            client_name=client_name,
            session_key=session_key_alice_bob,
            timestamp=time.time()
        )
        encrypted_bob_ticket = encrypt(bob_key, ticket_for_bob.serialize())

        # Ответ TGS: (сессионный ключ K_Alice_Bob, билет для Боба) зашифрованные сессионным ключом Алисы-TGS
        response_plain = session_key_alice_bob + b"||" + encrypted_bob_ticket
        encrypted_response = encrypt(ticket.session_key, response_plain)

        return encrypted_response

class ServiceServer:
    """Сервер, предоставляющий услуги (Боб)"""
    def __init__(self, name: str, password: str):
        self.name = name
        self.secret_key = derive_key_from_password(password)

    def handle_request(self, encrypted_ticket: bytes, authenticator: bytes) -> Optional[bytes]:
        """
        Шаг 5-6: Боб принимает билет (зашифрованный ключом Боба) и аутентификатор.
        Возвращает подтверждение (опционально).
        """
        # Расшифровываем билет
        try:
            ticket_data = decrypt(self.secret_key, encrypted_ticket)
            ticket = Ticket.deserialize(ticket_data)
        except Exception:
            return None

        # Проверяем время жизни
        if time.time() - ticket.timestamp > ticket.lifetime:
            return None

        # Расшифровываем аутентификатор (должен быть зашифрован сессионным ключом из билета)
        try:
            auth_data = decrypt(ticket.session_key, authenticator)
            client_name, client_timestamp = auth_data.decode().split('|')
        except Exception:
            return None

        # Проверка имени и временной метки
        if client_name != ticket.client_name or abs(time.time() - float(client_timestamp)) > 5.0:
            return None

        # Подтверждение (сообщение 6) – шифруем timestamp +1
        confirm = str(float(client_timestamp) + 1).encode()
        encrypted_confirm = encrypt(ticket.session_key, confirm)
        return encrypted_confirm

# ---------------------- Клиент (Алиса) ----------------------
class AliceClient:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session_key_tgs: Optional[bytes] = None
        self.session_key_bob: Optional[bytes] = None

    def authenticate_to_as(self, as_server: AuthenticationServer, tgs_name: str) -> bool:
        """Шаг 1-2: получаем TGT от AS"""
        encrypted_response = as_server.handle_request(self.username, tgs_name)
        if not encrypted_response:
            return False

        # Расшифровываем ответ AS своим долговременным ключом
        my_key = derive_key_from_password(self.password)
        try:
            plain_response = decrypt(my_key, encrypted_response)
            # Разбираем: session_key_tgs || "||" || encrypted_ticket
            parts = plain_response.split(b"||")
            if len(parts) != 2:
                return False
            self.session_key_tgs = parts[0]
            self.encrypted_ticket_for_tgs = parts[1]
            return True
        except Exception:
            return False

    def request_service_ticket(self, tgs: TicketGrantingServer, service_name: str) -> bool:
        """Шаг 3-4: запрашиваем у TGS билет для сервиса (Боба)"""
        if not self.session_key_tgs:
            return False

        # Создаем аутентификатор (шифруем текущим сессионным ключом с TGS)
        authenticator = encrypt(self.session_key_tgs, f"{self.username}|{time.time()}".encode())

        encrypted_response = tgs.handle_request(self.encrypted_ticket_for_tgs, authenticator)
        if not encrypted_response:
            return False

        # Расшифровываем ответ TGS сессионным ключом с TGS
        try:
            plain_response = decrypt(self.session_key_tgs, encrypted_response)
            parts = plain_response.split(b"||")
            if len(parts) != 2:
                return False
            self.session_key_bob = parts[0]
            self.encrypted_ticket_for_bob = parts[1]
            return True
        except Exception:
            return False

    def access_service(self, bob: ServiceServer) -> bool:
        """Шаг 5-6: обращаемся к Бобу с билетом и аутентификатором"""
        if not self.session_key_bob:
            return False

        # Аутентификатор для Боба (шифруем сессионным ключом Алиса-Боб)
        authenticator = encrypt(self.session_key_bob, f"{self.username}|{time.time()}".encode())

        response = bob.handle_request(self.encrypted_ticket_for_bob, authenticator)
        if not response:
            return False

        # Расшифровываем подтверждение от Боба
        try:
            confirm = decrypt(self.session_key_bob, response)
            print(f"[Боб] Подтверждение получено: {confirm.decode()}")
            return True
        except Exception:
            return False

# ---------------------- Демонстрация работы ----------------------
if __name__ == "__main__":
    print("=== Симуляция протокола Kerberos (упрощенная) ===\n")

    # Инициализация серверов
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer("TGS1")
    bob_server = ServiceServer("Bob", "bob_secret")

    # Регистрация пользователей и сервисов
    as_server.register_user("Alice", "alice_password")
    tgs_server.register_service("Bob", "bob_secret")

    # Алиса входит в систему
    alice = AliceClient("Alice", "alice_password")

    # Шаг 1-2: аутентификация на AS, получение TGT
    print("1. Алиса запрашивает TGT у AS...")
    if alice.authenticate_to_as(as_server, "TGS1"):
        print("   TGT успешно получен.")
    else:
        print("   Ошибка аутентификации!")
        exit()

    # Шаг 3-4: запрос билета для Боба у TGS
    print("\n2. Алиса запрашивает у TGS билет для сервера Bob...")
    if alice.request_service_ticket(tgs_server, "Bob"):
        print("   Сервисный билет для Bob получен.")
    else:
        print("   Ошибка получения билета!")
        exit()

    # Шаг 5-6: доступ к Бобу
    print("\n3. Алиса обращается к серверу Bob...")
    if alice.access_service(bob_server):
        print("   Успешный доступ к ресурсам Боба.")
    else:
        print("   Доступ отклонен!")

    print("\n=== Протокол завершен ===")