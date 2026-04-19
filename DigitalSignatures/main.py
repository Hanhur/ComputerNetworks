import hashlib
import time
from dataclasses import dataclass
from typing import Dict, Set, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# ------------------- Вспомогательные функции -------------------
def generate_key_from_password(password: str) -> bytes:
    """Генерирует ключ Fernet на основе пароля."""
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = b'static_salt_for_demo',
        iterations = 100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# ------------------- Сущности -------------------
@dataclass
class Message:
    sender: str
    recipient: str
    nonce: int
    timestamp: float
    content: str

    def pack(self) -> str:
        return f"{self.sender}|{self.recipient}|{self.nonce}|{self.timestamp}|{self.content}"

    @staticmethod
    def unpack(data: str):
        parts = data.split('|')
        return Message(parts[0], parts[1], int(parts[2]), float(parts[3]), parts[4])


class User:
    def __init__(self, name: str, password: str):
        self.name = name
        self.secret_key = generate_key_from_password(password)
        self.cipher = Fernet(self.secret_key)

    def encrypt_for_bb(self, msg: Message) -> bytes:
        """Шифрует сообщение своим ключом."""
        return self.cipher.encrypt(msg.pack().encode())

    def decrypt_from_bb(self, encrypted_data: bytes) -> str:
        """Расшифровывает сообщение от BB."""
        return self.cipher.decrypt(encrypted_data).decode()


class Bob(User):
    """Боб - получатель сообщений (может быть банковским менеджером)."""
    pass


class Bank(Bob):
    """Банковский менеджер с защитой от повтора."""
    def __init__(self, name: str, password: str):
        super().__init__(name, password)
        self.recent_nonces: Set[str] = set()
        self.nonce_expiry = 3600

    def receive_order(self, encrypted_from_bb: bytes, bb: 'BigBrother') -> bool:
        """Банк проверяет подпись BB и защиту от повтора."""
        verified = bb.verify_bb_signature(encrypted_from_bb)
        if not verified:
            print(f"[{self.name}] Подпись BB недействительна!")
            return False

        parts = verified.split('|')
        if len(parts) != 4:
            return False
        
        _, sender_name, timestamp_str, order = parts
        timestamp = float(timestamp_str)

        # Защита от повтора по времени
        now = time.time()
        if now - timestamp > self.nonce_expiry:
            print(f"[{self.name}] Сообщение слишком старое.")
            return False

        # Защита от повтора по хешу
        msg_hash = hashlib.sha256(f"{sender_name}{timestamp}{order}".encode()).hexdigest()
        if msg_hash in self.recent_nonces:
            print(f"[{self.name}] Обнаружен повтор сообщения!")
            return False
        self.recent_nonces.add(msg_hash)

        print(f"\n[{self.name}] ЗАКАЗ ПРИНЯТ:")
        print(f"  Отправитель: {sender_name}")
        print(f"  Содержание: {order}")
        print(f"  Временная метка: {timestamp}")
        return True


class BigBrother:
    def __init__(self):
        self.users_db: Dict[str, Fernet] = {}
        self.bb_key = Fernet.generate_key()
        self.bb_cipher = Fernet(self.bb_key)

    def register_user(self, user: User):
        """Регистрация пользователя у BB."""
        self.users_db[user.name] = user.cipher
        print(f"[BB] Пользователь {user.name} зарегистрирован.")

    def process_signed_message(self, encrypted_from_alice: bytes, recipient_name: str) -> Optional[bytes]:
        """
        BB получает: K_A(B, RA, t, P)
        Отправляет: K_BB(A, t, P)
        """
        sender_name = None
        plaintext = None
        
        for name, cipher in self.users_db.items():
            try:
                plaintext = cipher.decrypt(encrypted_from_alice).decode()
                parts = plaintext.split('|')
                if len(parts) >= 2 and parts[1] == recipient_name:
                    sender_name = name
                    break
            except:
                continue

        if sender_name is None:
            print("[BB] Ошибка: не удалось расшифровать.")
            return None

        msg = Message.unpack(plaintext)
        print(f"[BB] Получено сообщение от {sender_name} для {msg.recipient}, nonce={msg.nonce}")

        # Формируем сообщение для получателя
        bb_message = f"BB_VERIFIED|{sender_name}|{msg.timestamp}|{msg.content}"
        encrypted_for_bob = self.bb_cipher.encrypt(bb_message.encode())
        return encrypted_for_bob

    def verify_bb_signature(self, encrypted_data: bytes) -> Optional[str]:
        """Проверка подписи BB."""
        try:
            plaintext = self.bb_cipher.decrypt(encrypted_data).decode()
            if plaintext.startswith("BB_VERIFIED|"):
                return plaintext
        except:
            pass
        return None


# ------------------- Демонстрация -------------------
if __name__ == "__main__":
    print("=== СИСТЕМА ЦИФРОВЫХ ПОДПИСЕЙ С BIG BROTHER ===\n")

    # 1. Инициализация
    bb = BigBrother()
    
    alice = User("Alice", "alice_secret_pass")
    bob = Bank("Bob", "bob_secret_pass")
    
    bb.register_user(alice)
    bb.register_user(bob)

    # 2. Алиса создаёт заказ
    nonce = 12345
    timestamp = time.time()
    order_text = "Купить 1 тонну золота по текущей цене"
    
    msg_to_bob = Message(
        sender = "Alice",
        recipient = "Bob",
        nonce = nonce,
        timestamp = timestamp,
        content = order_text
    )
    
    encrypted_for_bb = alice.encrypt_for_bb(msg_to_bob)
    print(f"[Alice] Отправляю BB зашифрованное сообщение для Bob")

    # 3. BB обрабатывает
    bb_response = bb.process_signed_message(encrypted_for_bb, "Bob")
    if bb_response is None:
        print("Ошибка: BB не смог подтвердить подпись")
        exit(1)

    # 4. Боб получает заказ
    print(f"\n[Bob] Получено зашифрованное сообщение от BB")
    success = bob.receive_order(bb_response, bb)

    # 5. Судебное разбирательство (неотказуемость)
    print("\n=== СУДЕБНОЕ РАЗБИРАТЕЛЬСТВО ===")
    print("Алиса отрицает отправку заказа.")
    
    court_evidence = bb_response
    judge_verdict = bb.verify_bb_signature(court_evidence)
    
    if judge_verdict:
        print("  BB подтверждает: сообщение подписано BB.")
        print("  Суд: В пользу Боба. Неотказуемость обеспечена.")
    else:
        print("  Подпись BB неверна.")

    # 6. Атака повторным воспроизведением
    print("\n=== АТАКА ПОВТОРОМ ===")
    print("Труди пытается повторить старое сообщение...")
    success_again = bob.receive_order(bb_response, bb)
    
    if not success_again:
        print("✓ Атака отражена: Боб отклонил повтор.")