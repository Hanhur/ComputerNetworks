"""
Симуляция SYN-флуд атаки и защиты SYN cookies
Только для образовательных целей в изолированной среде!
"""

import hashlib
import time
import random
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional


# ============================================================
# ЧАСТЬ 1: СИМУЛЯЦИЯ СЕРВЕРА С SYN COOKIES
# ============================================================

class SYN_Cookie_Generator:
    """Реализация SYN cookies согласно описанию (упрощённая, но отражающая суть)"""
    
    def __init__(self):
        self.secret_key = b"my_super_secret_key_for_syn_cookies_2026"
        self.time_counter = 0
        self.last_time_update = time.time()
        
    def _get_timestamp(self) -> int:
        """Медленно возрастающий таймер (интервал 64 секунды по тексту)"""
        current = int(time.time() / 64)  # увеличивается раз в 64 секунды
        return current & 0x1F  # первые 5 бит (0-31)
    
    def _get_mss_code(self, mss: int) -> int:
        """Кодирует MSS в 3 бита (8 возможных значений)"""
        # Стандартные значения MSS
        mss_options = [536, 1460, 896, 1024, 1280, 1400, 1450, 1500]
        # Находим ближайшее или возвращаем индекс 1 (1460) по умолчанию
        for i, opt in enumerate(mss_options):
            if mss <= opt:
                return i
        return 1  # 1460 по умолчанию
    
    def _get_mss_from_code(self, code: int) -> int:
        """Декодирует MSS из 3 бит"""
        mss_options = [536, 1460, 896, 1024, 1280, 1400, 1450, 1500]
        return mss_options[code & 0x07]
    
    def _compute_hash(self, timestamp: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> int:
        """Криптографический хеш (24 бита)"""
        data = f"{timestamp}:{src_ip}:{dst_ip}:{src_port}:{dst_port}".encode()
        hash_obj = hashlib.sha256(self.secret_key + data)
        # Берём первые 24 бита (3 байта) хеша
        hash_bytes = hash_obj.digest()[:3]
        return int.from_bytes(hash_bytes, byteorder='big')
    
    def generate_cookie(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, mss: int) -> int:
        """
        Генерирует SYN cookie (32-битный порядковый номер)
        Биты: [31:27] таймер | [26:24] MSS код | [23:0] хеш
        """
        timestamp = self._get_timestamp()
        mss_code = self._get_mss_code(mss)
        hash_val = self._compute_hash(timestamp, src_ip, dst_ip, src_port, dst_port)
        
        # Сборка 32-битного числа
        cookie = (timestamp << 27) | (mss_code << 24) | (hash_val & 0xFFFFFF)
        return cookie
    
    def validate_cookie(self, cookie: int, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[int]:
        """
        Проверяет cookie и возвращает MSS, если валиден, иначе None
        """
        timestamp = (cookie >> 27) & 0x1F
        mss_code = (cookie >> 24) & 0x07
        received_hash = cookie & 0xFFFFFF
        
        # Проверяем текущее и предыдущее значение таймера (устойчивость к смещению)
        current_ts = self._get_timestamp()
        for ts in [current_ts, (current_ts - 1) & 0x1F]:
            expected_hash = self._compute_hash(ts, src_ip, dst_ip, src_port, dst_port)
            if expected_hash == received_hash:
                return self._get_mss_from_code(mss_code)
        return None


class VulnerableServer:
    """Сервер без защиты SYN cookies — уязвимый к SYN-флуду"""
    
    def __init__(self, max_half_open: int = 10):
        self.max_half_open = max_half_open
        self.half_open_connections = {}  # key -> (src_ip, src_port, mss)
        self.established_connections = set()
        self.dropped_count = 0
        
    def handle_syn(self, src_ip: str, src_port: int, dst_port: int, mss: int) -> bool:
        """Обработка SYN пакета. Возвращает True, если соединение добавлено"""
        if len(self.half_open_connections) >= self.max_half_open:
            self.dropped_count += 1
            return False  # Сервер перегружен, SYN отброшен
        
        conn_id = (src_ip, src_port, dst_port)
        self.half_open_connections[conn_id] = (src_ip, src_port, mss, time.time())
        return True
    
    def handle_ack(self, src_ip: str, src_port: int, dst_port: int) -> bool:
        """Завершение рукопожатия (третий пакет)"""
        conn_id = (src_ip, src_port, dst_port)
        if conn_id in self.half_open_connections:
            del self.half_open_connections[conn_id]
            self.established_connections.add(conn_id)
            return True
        return False
    
    def get_stats(self):
        return {
            "half_open": len(self.half_open_connections),
            "established": len(self.established_connections),
            "dropped_syn": self.dropped_count
        }


class ProtectedServer:
    """Сервер с защитой SYN cookies"""
    
    def __init__(self):
        self.syn_cookie_gen = SYN_Cookie_Generator()
        self.established_connections = set()
        self.cookies_sent = 0
        self.valid_acks = 0
        
    def handle_syn(self, src_ip: str, src_port: int, dst_port: int, mss: int) -> int:
        """Обработка SYN — генерируем cookie и не сохраняем состояние"""
        cookie = self.syn_cookie_gen.generate_cookie(src_ip, "server_ip", src_port, dst_port, mss)
        self.cookies_sent += 1
        return cookie  # Сервер отправляет этот cookie в пакете SYN/ACK
    
    def handle_ack(self, src_ip: str, src_port: int, dst_port: int, ack_cookie: int) -> bool:
        """
        Обработка ACK с cookie. Восстанавливаем состояние без хранения ранее.
        """
        mss = self.syn_cookie_gen.validate_cookie(ack_cookie - 1, src_ip, "server_ip", src_port, dst_port)
        if mss is not None:
            conn_id = (src_ip, src_port, dst_port)
            self.established_connections.add(conn_id)
            self.valid_acks += 1
            return True
        return False
    
    def get_stats(self):
        return {
            "cookies_sent": self.cookies_sent,
            "established": len(self.established_connections),
            "valid_acks": self.valid_acks
        }


# ============================================================
# ЧАСТЬ 2: СИМУЛЯЦИЯ SYN-ФЛУД АТАКИ
# ============================================================

class Attacker:
    """Злоумышленник, отправляющий SYN-пакеты (симуляция)"""
    
    def __init__(self, name: str, use_spoofed_ips: bool = True):
        self.name = name
        self.use_spoofed_ips = use_spoofed_ips
        self.sent_packets = 0
        
    def syn_flood(self, server, target_port: int, num_packets: int, mss: int = 1460):
        """
        Симуляция SYN-флуда. server может быть уязвимым или защищённым.
        """
        print(f"\n[{self.name}] Начинает SYN-флуд: {num_packets} пакетов, порт {target_port}")
        print(f"      Использовать поддельные IP: {self.use_spoofed_ips}")
        
        for i in range(num_packets):
            # Генерация IP-адреса (реального или поддельного)
            if self.use_spoofed_ips:
                src_ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            else:
                src_ip = f"192.168.1.{random.randint(2, 100)}"
            
            src_port = random.randint(1024, 65535)
            
            if isinstance(server, VulnerableServer):
                server.handle_syn(src_ip, src_port, target_port, mss)
            elif isinstance(server, ProtectedServer):
                # Для защищённого сервера атака всё равно возможна, но не истощает память
                server.handle_syn(src_ip, src_port, target_port, mss)
            
            self.sent_packets += 1
            
            # Небольшая задержка для реалистичности (в реальной атаке её нет)
            # Здесь оставляем для читаемости вывода
            if i % 100 == 0 and i > 0:
                print(f"   ... отправлено {i} SYN-пакетов")
        
        print(f"[{self.name}] Атака завершена. Отправлено пакетов: {self.sent_packets}")


# ============================================================
# ЧАСТЬ 3: ЛЕГИТИМНЫЙ КЛИЕНТ
# ============================================================

class LegitimateClient:
    """Обычный пользователь, пытающийся подключиться к серверу"""
    
    def __init__(self, ip: str):
        self.ip = ip
        
    def connect_to_vulnerable(self, server: VulnerableServer, port: int, mss: int = 1460) -> bool:
        """Попытка подключения к уязвимому серверу"""
        src_port = random.randint(1024, 65535)
        # Шаг 1: SYN
        success = server.handle_syn(self.ip, src_port, port, mss)
        if not success:
            print(f"  Клиент {self.ip}: SYN отброшен (сервер перегружен)")
            return False
        # Шаг 2: ACK
        return server.handle_ack(self.ip, src_port, port)
    
    def connect_to_protected(self, server: ProtectedServer, port: int, mss: int = 1460) -> bool:
        """Попытка подключения к защищённому серверу"""
        src_port = random.randint(1024, 65535)
        # Шаг 1: SYN -> получаем cookie
        cookie = server.handle_syn(self.ip, src_port, port, mss)
        # Шаг 2: ACK с cookie
        return server.handle_ack(self.ip, src_port, port, cookie + 1)


# ============================================================
# ЧАСТЬ 4: ДЕМОНСТРАЦИЯ
# ============================================================

def run_demonstration():
    print("=" * 70)
    print("СИМУЛЯЦИЯ SYN-ФЛУД АТАКИ И ЗАЩИТЫ SYN COOKIES")
    print("=" * 70)
    
    # 1. Уязвимый сервер под атакой
    print("\n\n[ТЕСТ 1] УЯЗВИМЫЙ СЕРВЕР ПОД SYN-ФЛУДОМ")
    print("-" * 50)
    vuln_server = VulnerableServer(max_half_open = 5)  # Маленькая очередь
    attacker = Attacker("Злоумышленник", use_spoofed_ips = True)
    
    # Атака
    attacker.syn_flood(vuln_server, target_port = 80, num_packets = 20)
    
    # Легитимный клиент пытается подключиться
    print("\n[Легитимный клиент] Попытка подключиться...")
    client = LegitimateClient("10.0.0.100")
    success = client.connect_to_vulnerable(vuln_server, port = 80)
    print(f"Результат подключения: {'УСПЕШНО' if success else 'ОТКЛОНЕНО (отказ в обслуживании)'}")
    
    print(f"\nСтатистика уязвимого сервера: {vuln_server.get_stats()}")
    
    # 2. Защищённый сервер под атакой
    print("\n\n[ТЕСТ 2] ЗАЩИЩЁННЫЙ СЕРВЕР (SYN COOKIES) ПОД SYN-ФЛУДОМ")
    print("-" * 50)
    protected_server = ProtectedServer()
    attacker2 = Attacker("Злоумышленник", use_spoofed_ips = True)
    
    # Атака
    attacker2.syn_flood(protected_server, target_port = 80, num_packets = 100)
    
    # Легитимный клиент подключается успешно
    print("\n[Легитимный клиент] Попытка подключиться...")
    client2 = LegitimateClient("10.0.0.200")
    success2 = client2.connect_to_protected(protected_server, port = 80)
    print(f"Результат подключения: {'УСПЕШНО' if success2 else 'ОТКЛОНЕНО'}")
    
    print(f"\nСтатистика защищённого сервера: {protected_server.get_stats()}")
    
    # 3. Демонстрация работы SYN cookie
    print("\n\n[ТЕСТ 3] ДЕТАЛЬНАЯ ДЕМОНСТРАЦИЯ ГЕНЕРАЦИИ SYN COOKIE")
    print("-" * 50)
    syn_cookie = SYN_Cookie_Generator()
    
    src_ip = "192.168.1.10"
    dst_ip = "10.0.0.1"
    src_port = 12345
    dst_port = 80
    mss = 1460
    
    cookie = syn_cookie.generate_cookie(src_ip, dst_ip, src_port, dst_port, mss)
    print(f"Исходные данные:")
    print(f"  Source IP: {src_ip}, Source Port: {src_port}")
    print(f"  Dest IP: {dst_ip}, Dest Port: {dst_port}")
    print(f"  MSS: {mss}")
    print(f"\nСгенерированный SYN cookie (32-битный порядковый номер): {cookie} (0x{cookie:08X})")
    
    # Проверка
    restored_mss = syn_cookie.validate_cookie(cookie, src_ip, dst_ip, src_port, dst_port)
    print(f"\nПроверка cookie сервером при получении ACK:")
    print(f"  Восстановленный MSS: {restored_mss}")
    print(f"  Совпадает с исходным: {restored_mss == mss}")
    
    # Поддельный cookie
    fake_cookie = cookie ^ 0xFFFFFFFF
    print(f"\nПопытка с поддельным cookie (0x{fake_cookie:08X}):")
    fake_restored = syn_cookie.validate_cookie(fake_cookie, src_ip, dst_ip, src_port, dst_port)
    print(f"  Результат проверки: {'НЕДЕЙСТВИТЕЛЬНО' if fake_restored is None else f'MSS={fake_restored}'}")
    
    print("\n" + "=" * 70)
    print("ВЫВОД: SYN cookies позволяют серверу не хранить состояние полуоткрытых")
    print("       соединений, эффективно защищая от SYN-флуда с поддельными IP.")
    print("=" * 70)


if __name__ == "__main__":
    print("\n⚠️  ВНИМАНИЕ: Эта программа создана ТОЛЬКО для образовательных целей!")
    print("   Используйте её только на своих собственных системах или в")
    print("   изолированной лабораторной среде.\n")
    
    choice = input("Введите 'run' для запуска демонстрации: ").strip().lower()
    if choice == 'run':
        run_demonstration()
    else:
        print("Демонстрация отменена.")