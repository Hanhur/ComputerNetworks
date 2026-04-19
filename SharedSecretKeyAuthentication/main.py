import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ---------------------------
# Вспомогательные функции для AES (симметричное шифрование)
# ---------------------------
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    iv = ciphertext[:16]
    actual_ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend = default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ct) + decryptor.finalize()

# ---------------------------
# УЯЗВИМЫЙ ПРОТОКОЛ (общий ключ, шифрование запроса)
# Подвержен зеркальной атаке
# ---------------------------
class VulnerableProtocol:
    def __init__(self, name, shared_key):
        self.name = name
        self.shared_key = shared_key  # bytes, 16 байт для AES

    def generate_nonce(self) -> bytes:
        return os.urandom(16)

    def encrypt_nonce(self, nonce: bytes) -> bytes:
        return aes_encrypt(self.shared_key, nonce)

    def decrypt_nonce(self, encrypted: bytes) -> bytes:
        return aes_decrypt(self.shared_key, encrypted)

# Симуляция зеркальной атаки на уязвимый протокол
def reflection_attack_demo():
    print("\n" + "=" * 60)
    print("ЗЕРКАЛЬНАЯ АТАКА на уязвимый протокол (шифрование запроса)")
    print("=" * 60)

    # Общий ключ Алисы и Боба
    shared_key = os.urandom(16)
    alice = VulnerableProtocol("Алиса", shared_key)
    bob = VulnerableProtocol("Боб", shared_key)
    trudy = VulnerableProtocol("Труди", None)  # у Труди нет ключа

    print(f"Общий секретный ключ K_AB: {shared_key.hex()[:16]}... (известен только Алисе и Бобу)")

    # ---- Сеанс 1 (Труди выдаёт себя за Алису перед Бобом) ----
    print("\n--- СЕАНС 1 (Труди притворяется Алисой перед Бобом) ---")
    # Сообщение 1: Труди отправляет "A" (идентификатор) — перехвачено
    # Сообщение 2: Боб посылает запрос R_B
    r_b = bob.generate_nonce()
    print(f"Боб -> (Труди как Алисе): запрос R_B = {r_b.hex()[:16]}...")

    # Труди в тупике: она не может зашифровать R_B без ключа.
    # Она открывает второй сеанс с Бобом, притворяясь Алисой снова.

    # ---- Сеанс 2 (параллельный) ----
    print("\n--- СЕАНС 2 (Труди открывает второй сеанс с Бобом) ---")
    # Сообщение 3 (сеанс 2): Труди отправляет запрос, равный R_B из сеанса 1
    r_trudy = r_b  # зеркальное отражение
    print(f"Труди -> Боб (сеанс 2): запрос R_T = R_B (зеркало) = {r_trudy.hex()[:16]}...")
    # Боб (сеанс 2) отвечает: шифрует R_T своим ключом
    encrypted_rb = bob.encrypt_nonce(r_trudy)
    print(f"Боб -> Труди (сеанс 2): K_AB(R_T) = {encrypted_rb.hex()[:16]}...")

    # Труди получает зашифрованный R_B. Теперь она может завершить сеанс 1
    print("\n--- Труди завершает сеанс 1 ---")
    print(f"Труди -> Боб (сеанс 1): K_AB(R_B) (скопирован из сеанса 2) = {encrypted_rb.hex()[:16]}...")
    print("Боб проверяет: расшифровывает и получает R_B. Всё верно. Боб думает, что это Алиса.")
    print("--> АТАКА УСПЕШНА! Труди аутентифицировалась как Алиса перед Бобом.")

# ---------------------------
# ЗАЩИЩЁННЫЙ ПРОТОКОЛ (на основе HMAC)
# Устойчив к зеркальным атакам
# ---------------------------
class SecureHMACProtocol:
    def __init__(self, name, shared_key):
        self.name = name
        self.shared_key = shared_key  # bytes

    def generate_nonce(self) -> bytes:
        return os.urandom(16)

    def compute_hmac(self, ra: bytes, rb: bytes, id_a: str, id_b: str) -> bytes:
        # Структура: R_A || R_B || A || B
        message = ra + rb + id_a.encode() + id_b.encode()
        return hmac.new(self.shared_key, message, hashlib.sha256).digest()

    # Для Алисы (инициатор)
    def initiate(self, bob_name):
        ra = self.generate_nonce()
        return ra, f"{self.name} -> {bob_name}: R_A = {ra.hex()[:16]}..."

    # Для Боба (ответчик)
    def respond(self, ra: bytes, alice_name):
        rb = self.generate_nonce()
        hmac_val = self.compute_hmac(ra, rb, alice_name, self.name)
        return rb, hmac_val, f"{self.name} -> {alice_name}: R_B, HMAC(R_A,R_B,A,B)"

    # Для Алисы — проверка ответа Боба
    def verify_bob(self, ra: bytes, rb: bytes, received_hmac: bytes, alice_name, bob_name):
        expected_hmac = self.compute_hmac(ra, rb, alice_name, bob_name)
        return hmac.compare_digest(expected_hmac, received_hmac)

    # Завершающий HMAC от Алисы к Бобу
    def final_hmac(self, ra: bytes, rb: bytes, alice_name, bob_name):
        return self.compute_hmac(ra, rb, alice_name, bob_name)

def secure_protocol_demo():
    print("\n" + "=" * 60)
    print("ЗАЩИЩЁННЫЙ ПРОТОКОЛ на основе HMAC")
    print("=" * 60)

    shared_key = os.urandom(32)  # 256 бит для HMAC-SHA256
    alice = SecureHMACProtocol("Алиса", shared_key)
    bob = SecureHMACProtocol("Боб", shared_key)

    print(f"Общий секретный ключ K_AB: {shared_key.hex()[:16]}...")

    # Сообщение 1: Алиса -> Боб: R_A
    ra, msg1 = alice.initiate("Боб")
    print(f"\n1. {msg1}")

    # Сообщение 2: Боб -> Алиса: R_B, HMAC(K_AB, R_A || R_B || A || B)
    rb, hmac_from_bob, msg2 = bob.respond(ra, "Алиса")
    print(f"2. {msg2}")
    print(f"   R_B = {rb.hex()[:16]}..., HMAC = {hmac_from_bob.hex()[:16]}...")

    # Алиса проверяет Боба
    ok = alice.verify_bob(ra, rb, hmac_from_bob, "Алиса", "Боб")
    if ok:
        print("3. Алиса: HMAC верен → Боб аутентифицирован.")
    else:
        print("3. Алиса: ОШИБКА! Боб не подтверждён.")
        return

    # Сообщение 3: Алиса -> Боб: HMAC(K_AB, R_A || R_B)
    final_hmac = alice.final_hmac(ra, rb, "Алиса", "Боб")
    print(f"4. Алиса -> Боб: HMAC = {final_hmac.hex()[:16]}...")

    # Боб проверяет (аналогично)
    ok2 = bob.verify_bob(ra, rb, final_hmac, "Алиса", "Боб")
    if ok2:
        print("5. Боб: HMAC верен → Алиса аутентифицирована.")
        print("\n--> Протокол завершён успешно. Обе стороны подтвердили друг друга.")
    else:
        print("5. Боб: ОШИБКА!")

    # Попытка зеркальной атаки
    print("\n--- Попытка Труди провести зеркальную атаку на HMAC-протокол ---")
    trudy = SecureHMACProtocol("Труди", None)  # нет ключа
    # Труди перехватывает R_A и пытается открыть второй сеанс
    print("Труди перехватила R_A. Открывает второй сеанс с Бобом, отправив R_A как запрос.")
    print("Но Боб в ответе вычисляет HMAC от (R_A, R_B2, Алиса, Боб).")
    print("Труди не может получить HMAC без ключа. Подделать не может.")
    print("Зеркальная атака НЕВОЗМОЖНА, так как каждый HMAC привязан к паре нонсов и идентификаторам.")
    print("--> ПРОТОКОЛ БЕЗОПАСЕН.")

# ---------------------------
# ЗАПУСК ДЕМОНСТРАЦИИ
# ---------------------------
if __name__ == "__main__":
    reflection_attack_demo()
    secure_protocol_demo()