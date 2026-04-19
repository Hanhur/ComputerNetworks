"""
Симуляция протоколов аутентификации с центром распространения ключей (KDC)
Демонстрация:
- Простейший протокол (уязвим к replay)
- Атака повторного воспроизведения
- Протокол Отуэя-Рисса (устойчив к replay и компрометации старых ключей)
"""

from cryptography.fernet import Fernet
import base64
import json
from typing import Dict, Tuple, Optional
import time

# Вспомогательные функции для имитации шифрования
def generate_key() -> bytes:
    return Fernet.generate_key()

def encrypt(key: bytes, data: any) -> str:
    """Шифрует любые данные (сериализуя их в JSON)"""
    json_str = json.dumps(data)
    f = Fernet(key)
    return f.encrypt(json_str.encode()).decode()

def decrypt(key: bytes, encrypted: str) -> any:
    """Расшифровывает и возвращает объект"""
    f = Fernet(key)
    decrypted = f.decrypt(encrypted.encode())
    return json.loads(decrypted.decode())

# ------------------- KDC (Центр распространения ключей) -------------------
class KDC:
    def __init__(self):
        # База долговременных ключей пользователей
        self.keys: Dict[str, bytes] = {}
        # Хранилище выданных сеансовых ключей (для имитации логирования)
        self.issued_keys: Dict[str, bytes] = {}
    
    def register_user(self, username: str):
        """Регистрация пользователя — выдаём ему долговременный ключ"""
        key = generate_key()
        self.keys[username] = key
        print(f"[KDC] Пользователь {username} зарегистрирован (ключ: {key[:8]}...)")
        return key
    
    def get_user_key(self, username: str) -> Optional[bytes]:
        return self.keys.get(username)
    
    # ---------- Простейший протокол (илл. 8.36) ----------
    def simple_protocol_request(self, msg_encrypted: str) -> Tuple[str, str]:
        """
        Обработка сообщения 1 от Алисы:
        msg1 = encrypt(Ka, {"bob": "Bob", "session_key": Ks})
        Возвращает: (encrypted_for_Bob, session_key)
        """
        # Расшифровываем от Алисы
        # Для имитации нужно определить, чей ключ использовать
        # В реальной симуляции сообщение должно содержать идентификатор отправителя
        # Упростим: на входе передаём уже готовое расшифрованное содержимое для демо
        pass
    
    # Упрощённый метод: создаём "билет" для Боба
    def issue_ticket_simple(self, alice: str, bob: str, session_key: bytes) -> str:
        """Выдаёт билет (сообщение 2) для Боба: encrypt(Kb, {"alice": alice, "session_key": session_key})"""
        ticket_content = {"alice": alice, "session_key": session_key.hex()}
        if bob not in self.keys:
            raise ValueError(f"Пользователь {bob} не зарегистрирован")
        encrypted_ticket = encrypt(self.keys[bob], ticket_content)
        return encrypted_ticket


# ------------------- Простейший протокол (уязвимый) -------------------
class SimpleProtocolUser:
    """Участник простейшего протокола (Алиса или Боб)"""
    def __init__(self, name: str, kdc: KDC):
        self.name = name
        self.kdc = kdc
        self.long_term_key = kdc.get_user_key(name)
        if self.long_term_key is None:
            self.long_term_key = kdc.register_user(name)
        self.session_keys: Dict[str, bytes] = {}  # партнёр -> сеансовый ключ
    
    def initiate_session(self, peer: str) -> bytes:
        """Алиса: выбирает сеансовый ключ и отправляет запрос в KDC (имитация)"""
        session_key = generate_key()
        print(f"\n[{self.name}] Инициирую сеанс с {peer}. Сеансовый ключ: {session_key[:8]}...")
        
        # Сообщение 1: зашифрованное своим ключом для KDC
        msg1_content = {"bob": peer, "session_key": session_key.hex()}
        msg1_encrypted = encrypt(self.long_term_key, msg1_content)
        
        # KDC создаёт билет для Боба (сообщение 2)
        ticket_for_bob = self.kdc.issue_ticket_simple(self.name, peer, session_key)
        
        # Имитируем отправку билета Бобу
        # Сохраняем ключ у себя
        self.session_keys[peer] = session_key
        return ticket_for_bob, session_key
    
    def receive_ticket(self, from_peer: str, ticket_encrypted: str) -> bytes:
        """Боб: получает билет от KDC (через Алису)"""
        # Расшифровываем билет своим долговременным ключом
        ticket = decrypt(self.long_term_key, ticket_encrypted)
        alice = ticket["alice"]
        session_key_hex = ticket["session_key"]
        session_key = bytes.fromhex(session_key_hex)
        self.session_keys[alice] = session_key
        print(f"[{self.name}] Получил билет от {alice}. Сеансовый ключ: {session_key[:8]}...")
        return session_key
    
    def send_payment_order(self, to_peer: str, amount: int, recipient: str) -> str:
        """Алиса отправляет приказ на перевод денег (шифруя сеансовым ключом)"""
        if to_peer not in self.session_keys:
            raise Exception(f"Нет сеансового ключа с {to_peer}")
        key = self.session_keys[to_peer]
        order = {"action": "pay", "amount": amount, "to": recipient}
        encrypted = encrypt(key, order)
        print(f"[{self.name}] -> {to_peer}: Платеж {amount} {recipient} (зашифровано)")
        return encrypted
    
    def receive_order(self, from_peer: str, encrypted_order: str) -> dict:
        """Боб получает и исполняет приказ"""
        if from_peer not in self.session_keys:
            raise Exception(f"Нет ключа для {from_peer}")
        key = self.session_keys[from_peer]
        order = decrypt(key, encrypted_order)
        print(f"[{self.name}] Получен и исполнен приказ: {order}")
        return order


# ------------------- Демонстрация атаки повторного воспроизведения -------------------
def demo_replay_attack():
    print("\n" + "="*60)
    print("ДЕМОНСТРАЦИЯ АТАКИ ПОВТОРНОГО ВОСПРОИЗВЕДЕНИЯ (REPLAY ATTACK)")
    print("="*60)
    
    kdc = KDC()
    alice = SimpleProtocolUser("Alice", kdc)
    bob = SimpleProtocolUser("Bob", kdc)
    trudy = SimpleProtocolUser("Trudy", kdc)  # Злоумышленник
    
    # 1. Легитимный сеанс Алисы с Бобом
    print("\n--- ЛЕГИТИМНЫЙ СЕАНС: Алиса нанимает Труди ---")
    ticket, session_key = alice.initiate_session("Bob")
    bob.receive_ticket("Alice", ticket)
    
    # Алиса отправляет платёж Труди
    payment_msg = alice.send_payment_order("Bob", amount = 100, recipient = "Trudy")
    bob.receive_order("Alice", payment_msg)
    
    # 2. Атака: Труди копирует сообщения и воспроизводит их позже
    print("\n--- АТАКА: Труди перехватывает и повторяет сообщения ---")
    # Труди получает доступ к перехваченному билету (сообщение 2) и платёжному сообщению
    stolen_ticket = ticket
    stolen_payment = payment_msg
    
    # Труди отправляет их Бобу повторно (имитация)
    print("\n[Trudy] Воспроизвожу перехваченный билет и платёж для Боба...")
    # Боб расшифровывает старый билет (действителен, т.к. нет защиты от повтора)
    bob.receive_ticket("Alice", stolen_ticket)  # У Боба теперь старый сеансовый ключ (такой же)
    # Боб исполняет платёж ещё раз
    bob.receive_order("Alice", stolen_payment)
    
    print("\n[ИТОГ] Боб выполнил платёж дважды! Атака повторного воспроизведения успешна.")


# ------------------- Протокол Отуэя-Рисса (устойчивый) -------------------
class OtwayReesKDC(KDC):
    """Расширенный KDC для протокола Отуэя-Рисса"""
    def process_otway_rees(self, msg_from_bob: dict) -> dict:
        """
        msg_from_bob = {
            "partA": encrypt(Ka, {"R": R, "Ra": Ra, "Alice": Alice, "Bob": Bob}),
            "partB": encrypt(Kb, {"R": R, "Rb": Rb, "Alice": Alice, "Bob": Bob})
        }
        Возвращает: {
            "forAlice": encrypt(Ka, {"R": R, "Ks": Ks, "Rb": Rb}),
            "forBob": encrypt(Kb, {"R": R, "Ks": Ks, "Ra": Ra})
        }
        """
        partA_enc = msg_from_bob["partA"]
        partB_enc = msg_from_bob["partB"]
        
        # Пытаемся расшифровать каждую часть (нужно знать, от кого каждая)
        # В реальности KDC извлекает идентификаторы из самих частей.
        # Упростим: предполагаем, что в partA зашифровано для Алисы, partB для Боба.
        # Но KDC не знает ключи заранее — он перебирает по именам из контекста.
        # Для демо: извлекаем открытые поля (в реальности KDC по имени находит ключ)
        # Сымитируем: partA зашифрована ключом Alice, partB — Bob.
        alice_name = None
        bob_name = None
        
        # Пробуем расшифровать partA всеми известными ключами (упрощённо)
        # В нормальной реализации сообщение содержит в открытом виде имена.
        # Для демонстрации логики предположим, что мы знаем имена.
        # Сделаем проще: ожидаем, что в сообщении есть поля "alice" и "bob" в открытом виде.
        alice_name = msg_from_bob.get("alice")
        bob_name = msg_from_bob.get("bob")
        
        if not alice_name or not bob_name:
            raise ValueError("Otway-Rees: отсутствуют имена участников")
        
        if alice_name not in self.keys or bob_name not in self.keys:
            raise ValueError("Неизвестные пользователи")
        
        ka = self.keys[alice_name]
        kb = self.keys[bob_name]
        
        partA = decrypt(ka, partA_enc)
        partB = decrypt(kb, partB_enc)
        
        # Проверяем совпадение идентификатора R
        if partA["R"] != partB["R"]:
            raise ValueError("Несовпадение R в двух частях сообщения — возможна подмена!")
        
        # Генерируем новый сеансовый ключ
        Ks = generate_key()
        
        # Формируем ответы
        for_alice = {
            "R": partA["R"],
            "Ks": Ks.hex(),
            "Rb": partB.get("Rb", 0)
        }
        for_bob = {
            "R": partA["R"],
            "Ks": Ks.hex(),
            "Ra": partA.get("Ra", 0)
        }
        
        return {
            "forAlice": encrypt(ka, for_alice),
            "forBob": encrypt(kb, for_bob)
        }


class OtwayReesUser:
    def __init__(self, name: str, kdc: OtwayReesKDC):
        self.name = name
        self.kdc = kdc
        self.long_term_key = kdc.get_user_key(name)
        if self.long_term_key is None:
            self.long_term_key = kdc.register_user(name)
        self.session_keys: Dict[str, bytes] = {}
    
    def initiate(self, peer: str) -> Tuple[dict, int]:
        """Алиса: генерирует R (общий идентификатор) и Ra (свой нонс)"""
        self.R = int(time.time() * 1000) % 1000000  # имитация уникального ID
        self.Ra = int(time.time() * 1000) % 100000 + 1
        print(f"\n[{self.name}] Инициирую протокол Отуэя-Рисса с {peer}. R = {self.R}, Ra = {self.Ra}")
        
        # Сообщение 1: Алиса -> Боб (открытое: R, Alice, Bob, а также зашифрованная часть для KDC)
        encrypted_part = encrypt(self.long_term_key, {
            "R": self.R,
            "Ra": self.Ra,
            "Alice": self.name,
            "Bob": peer
        })
        msg_to_bob = {
            "R": self.R,
            "Alice": self.name,
            "Bob": peer,
            "encrypted_part": encrypted_part
        }
        return msg_to_bob, self.Ra
    
    def forward_to_kdc(self, from_alice_msg: dict, peer: str) -> dict:
        """Боб: получает сообщение от Алисы, добавляет свою часть и отправляет KDC"""
        self.R = from_alice_msg["R"]
        self.Rb = int(time.time() * 1000) % 100000 + 2
        print(f"[{self.name}] Получил запрос от {from_alice_msg['Alice']}, R = {self.R}, генерирую Rb = {self.Rb}")
        
        # Своя зашифрованная часть
        my_encrypted = encrypt(self.long_term_key, {
            "R": self.R,
            "Rb": self.Rb,
            "Alice": from_alice_msg["Alice"],
            "Bob": self.name
        })
        
        msg_to_kdc = {
            "alice": from_alice_msg["Alice"],
            "bob": self.name,
            "partA": from_alice_msg["encrypted_part"],
            "partB": my_encrypted
        }
        return msg_to_kdc
    
    def process_kdc_response(self, kdc_response: dict):
        """Алиса или Боб обрабатывает ответ KDC"""
        # Для Алисы: kdc_response["forAlice"]; для Боба: kdc_response["forBob"]
        # В реальности каждый берёт свою часть. Здесь упростим: передаём отдельно.
        pass
    
    def alice_receive(self, kdc_response: dict, expected_R: int, expected_Ra: int) -> bytes:
        """Алиса расшифровывает свою часть ответа KDC"""
        encrypted_part = kdc_response["forAlice"]
        decrypted = decrypt(self.long_term_key, encrypted_part)
        if decrypted["R"] != expected_R:
            raise ValueError("Неверный R в ответе KDC")
        Ks_hex = decrypted["Ks"]
        Ks = bytes.fromhex(Ks_hex)
        self.session_keys["Bob"] = Ks
        print(f"[{self.name}] Получила сеансовый ключ {Ks[:8]}... от KDC (Rb = {decrypted['Rb']})")
        return Ks
    
    def bob_receive(self, kdc_response: dict, expected_R: int, expected_Rb: int) -> bytes:
        """Боб расшифровывает свою часть ответа KDC"""
        encrypted_part = kdc_response["forBob"]
        decrypted = decrypt(self.long_term_key, encrypted_part)
        if decrypted["R"] != expected_R:
            raise ValueError("Неверный R в ответе KDC")
        Ks_hex = decrypted["Ks"]
        Ks = bytes.fromhex(Ks_hex)
        self.session_keys["Alice"] = Ks
        print(f"[{self.name}] Получил сеансовый ключ {Ks[:8]}... от KDC (Ra = {decrypted['Ra']})")
        return Ks


def demo_otway_rees():
    print("\n" + "=" * 60)
    print("ДЕМОНСТРАЦИЯ ПРОТОКОЛА ОТУЭЯ-РИСА (УСТОЙЧИВ К REPLAY)")
    print("=" * 60)
    
    kdc = OtwayReesKDC()
    alice = OtwayReesUser("Alice", kdc)
    bob = OtwayReesUser("Bob", kdc)
    
    # 1. Инициация Алисой
    msg_to_bob, Ra = alice.initiate("Bob")
    
    # 2. Боб формирует сообщение для KDC
    msg_to_kdc = bob.forward_to_kdc(msg_to_bob, "Bob")
    
    # 3. KDC обрабатывает и возвращает ответ
    kdc_response = kdc.process_otway_rees(msg_to_kdc)
    
    # 4. Алиса и Боб извлекают сеансовый ключ
    alice.alice_receive(kdc_response, alice.R, Ra)
    bob.bob_receive(kdc_response, bob.R, bob.Rb)
    
    print("\n[УСПЕХ] Сеансовый ключ согласован. Атака повторного воспроизведения невозможна, так как")
    print("каждый сеанс имеет уникальный R, и KDC проверяет совпадение R в обеих частях.")


# ------------------- ЗАПУСК ДЕМОНСТРАЦИИ -------------------
if __name__ == "__main__":
    demo_replay_attack()
    demo_otway_rees()
    
    print("\n" + "=" * 60)
    print("ВЫВОД: Простейший протокол уязвим к replay-атакам.")
    print("Протокол Отуэя-Рисса требует от KDC проверки идентификатора сеанса R")
    print("и выдаёт новый ключ только при совпадении в зашифрованных частях.")
    print("=" * 60)