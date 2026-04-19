#!/usr/bin/env python3
"""
ВНЕМАРШРУТНЫЙ ВЗЛОМ TCP (OFF-PATH TCP EXPLOIT)
Симуляция атаки на основе глобального лимита Challenge ACK (RFC 5961)

ВНИМАНИЕ: Это УЧЕБНАЯ симуляция, не выполняющая реальную отправку пакетов.
Она демонстрирует принцип побочного канала (side-channel attack).
Для реальной атаки требуются raw sockets и уязвимое ядро Linux.
"""

import random
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Optional, Dict


@dataclass(frozen=True)  # frozen=True делает объект неизменяемым и хешируемым
class Connection:
    """TCP-соединение на сервере"""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    seq_num: int = 0          # порядковый номер, который ожидает сервер
    ack_num: int = 0          # номер подтверждения
    window: int = 8192        # размер окна


class MutableConnection:
    """Изменяемая версия соединения для хранения состояния"""
    def __init__(self, conn: Connection):
        self.conn = conn
        self.seq_num = conn.seq_num
        self.ack_num = conn.ack_num
        self.window = conn.window
    
    def get_key(self):
        return self.conn


class VulnerableServer:
    """
    Сервер с уязвимой реализацией RFC 5961
    (глобальный счётчик challenge_acks_per_second)
    """
    
    def __init__(self):
        # Глобальный счётчик на все соединения (источник утечки!)
        self.challenge_acks_sent = 0
        self.last_reset_time = time.time()
        
        # Активные соединения (для симуляции) - используем словарь
        self.active_connections: Dict[Connection, MutableConnection] = {}
        
        # Для статистики
        self.stats = defaultdict(int)
    
    def _check_global_limit(self) -> bool:
        """Проверка глобального лимита: не более 100 challenge ACK в секунду"""
        now = time.time()
        if now - self.last_reset_time >= 1.0:
            self.challenge_acks_sent = 0
            self.last_reset_time = now
        
        if self.challenge_acks_sent >= 100:
            return False  # лимит исчерпан
        
        self.challenge_acks_sent += 1
        return True
    
    def _send_challenge_ack(self, packet_type: str, target: str):
        """Отправка challenge ACK реальному узлу"""
        self.stats["challenge_acks_sent"] += 1
        # В реальности пакет уходит настоящему клиенту
        # Атакующий этот пакет не получает!
    
    def _find_connection(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Optional[MutableConnection]:
        """Поиск существующего соединения"""
        key = Connection(
            src_ip = src_ip, src_port = src_port,
            dst_ip = dst_ip, dst_port = dst_port,
            seq_num = 0, ack_num = 0, window = 0
        )
        return self.active_connections.get(key)
    
    def receive_packet(self, 
                       src_ip: str, src_port: int,
                       dst_ip: str, dst_port: int,
                       packet_type: str,  # "SYN", "RST", "DATA"
                       seq: int = 0,
                       ack: int = 0,
                       data_len: int = 0) -> str:
        """
        Обработка входящего пакета по правилам RFC 5961
        Возвращает: "ACCEPT", "REJECT", "CHALLENGE", "RESET"
        """
        
        # Ищем существующее соединение
        conn = self._find_connection(src_ip, src_port, dst_ip, dst_port)
        
        # --- Случай 1: SYN пакет ---
        if packet_type == "SYN":
            if conn is None:
                # Новое соединение
                new_conn_key = Connection(
                    src_ip = src_ip, src_port = src_port,
                    dst_ip = dst_ip, dst_port = dst_port,
                    seq_num = seq + 1, ack_num = 0, window = 8192
                )
                self.active_connections[new_conn_key] = MutableConnection(new_conn_key)
                self.stats["new_connections"] += 1
                return "ACCEPT (NEW CONNECTION)"
            else:
                # Существующее соединение: по RFC 5961 отправляем challenge ACK
                if self._check_global_limit():
                    self._send_challenge_ack("SYN", src_ip)
                    return "CHALLENGE_ACK (SYN to existing connection)"
                else:
                    return "DROP (global limit exceeded)"
        
        # --- Случай 2: RST пакет ---
        if packet_type == "RST":
            if conn is None:
                return "REJECT (no such connection)"
            
            # Порядковый номер точно совпадает с ожидаемым? -> сброс
            if seq == conn.seq_num:
                del self.active_connections[conn.get_key()]
                self.stats["resets"] += 1
                return "RESET (exact match)"
            
            # Порядковый номер в пределах окна? -> challenge ACK
            if conn.seq_num <= seq < conn.seq_num + conn.window:
                if self._check_global_limit():
                    self._send_challenge_ack("RST", src_ip)
                    return "CHALLENGE_ACK (RST in window)"
                else:
                    return "DROP (global limit exceeded)"
            
            return "REJECT (RST out of window)"
        
        # --- Случай 3: DATA (с данными) ---
        if packet_type == "DATA":
            if conn is None:
                return "REJECT (no such connection)"
            
            # Проверка SEQ и ACK (упрощённо)
            seq_in_window = (conn.seq_num <= seq < conn.seq_num + conn.window)
            
            # Диапазон валидных ACK: [FUB - 2GB, FUB - MAXWIN] — упростим
            ack_valid = abs(ack - conn.ack_num) < 2 ** 30  # очень широкий диапазон
            
            if seq_in_window and ack_valid:
                # Принимаем данные
                conn.seq_num = seq + data_len
                self.stats["data_accepted"] += 1
                return "ACCEPT DATA"
            else:
                # Невалидный пакет -> challenge ACK
                if self._check_global_limit():
                    self._send_challenge_ack("DATA", src_ip)
                    return "CHALLENGE_ACK (invalid DATA)"
                else:
                    return "DROP (global limit exceeded)"
        
        return "UNKNOWN"
    
    def get_challenge_ack_count(self) -> int:
        """Получить количество отправленных challenge ACK"""
        return self.stats["challenge_acks_sent"]


class OffPathAttacker:
    """Внемаршрутный злоумышленник"""
    
    def __init__(self, server: VulnerableServer):
        self.server = server
        self.target_ip = "130.37.20.7"
        self.server_ip = "37.60.194.64"
        self.server_port = 80  # веб-сервер
    
    def probe_port(self, guessed_port: int, verbose: bool = True) -> bool:
        """
        Проверяет, использует ли клиент указанный порт.
        Возвращает True, если порт угадан верно.
        """
        # Сохраняем начальное состояние счётчика
        initial_acks = self.server.get_challenge_ack_count()
        
        # Шаг 1: Исчерпываем лимит challenge ACK
        for i in range(100):
            self.server.receive_packet(
                src_ip = self.target_ip, src_port = guessed_port,
                dst_ip = self.server_ip, dst_port = self.server_port,
                packet_type = "RST", seq = random.randint(0, 2 ** 32 - 1)
            )
        
        # Сколько ACK было отправлено после 100 RST?
        after_rst = self.server.get_challenge_ack_count()
        
        # Шаг 2: Отправляем поддельный SYN
        result = self.server.receive_packet(
            src_ip = self.target_ip, src_port = guessed_port,
            dst_ip = self.server_ip, dst_port = self.server_port,
            packet_type = "SYN", seq = 12345
        )
        
        # Сколько ACK после SYN?
        after_syn = self.server.get_challenge_ack_count()
        
        if verbose:
            print(f"  Порт {guessed_port}: {result}")
            print(f"    Challenge ACK: начально={initial_acks}, после RST={after_rst}, после SYN={after_syn}")
            print(f"    Прирост после SYN: {after_syn - after_rst}")
        
        # КЛЮЧЕВОЙ МОМЕНТ:
        # Если challenge ACK НЕ отправился (прирост 0), но результат говорит CHALLENGE,
        # значит, лимит был исчерпан и порт ВЕРНЫЙ!
        if "CHALLENGE" in result and after_syn == after_rst:
            return True
        
        return False
    
    def brute_force_port(self, port_range: range) -> Optional[int]:
        """Подбор порта через побочный канал"""
        print(f"[*] Подбор порта клиента на {self.target_ip}...")
        
        for port in port_range:
            if self.probe_port(port, verbose = False):
                print(f"[+] Порт найден: {port}")
                # Проверяем ещё раз с выводом
                self.probe_port(port, verbose = True)
                return port
        
        print("[-] Порт не найден")
        return None
    
    def demonstrate_side_channel(self):
        """Демонстрация принципа утечки через глобальный счётчик"""
        print("\n" + "=" * 60)
        print("ДЕМОНСТРАЦИЯ ПОБОЧНОГО КАНАЛА (SIDE-CHANNEL)")
        print("=" * 60)
        
        # Создаём реальное соединение на сервере
        real_port = 54321
        real_conn = Connection(
            src_ip = self.target_ip, src_port = real_port,
            dst_ip = self.server_ip, dst_port = self.server_port,
            seq_num = 1000, ack_num = 2000, window = 8192
        )
        self.server.active_connections[real_conn] = MutableConnection(real_conn)
        
        print(f"\n[СЕРВЕР] Активное соединение: {self.target_ip}:{real_port} -> {self.server_ip}:{self.server_port}")
        
        # Сбрасываем статистику
        self.server.stats["challenge_acks_sent"] = 0
        self.server.last_reset_time = time.time()
        self.server.challenge_acks_sent = 0
        
        print(f"\n[СЕРВЕР] Глобальный счётчик challenge ACK сброшен в 0")
        print(f"[СЕРВЕР] Лимит: 100 challenge ACK в секунду")
        
        # Пробуем неверный порт
        print(f"\n[АТАКУЮЩИЙ] Проверка НЕВЕРНОГО порта {real_port + 1}:")
        wrong_result = self.probe_port(real_port + 1, verbose=True)
        print(f"  Результат: порт {'УГАДАН' if wrong_result else 'НЕ угадан'}")
        
        # Сбрасываем счётчик для следующего теста
        self.server.stats["challenge_acks_sent"] = 0
        self.server.last_reset_time = time.time()
        self.server.challenge_acks_sent = 0
        
        # Пробуем верный порт
        print(f"\n[АТАКУЮЩИЙ] Проверка ВЕРНОГО порта {real_port}:")
        right_result = self.probe_port(real_port, verbose=True)
        print(f"  Результат: порт {'УГАДАН' if right_result else 'НЕ угадан'}")
        
        print("\n" + "-" * 60)
        print("ОБЪЯСНЕНИЕ ПОБОЧНОГО КАНАЛА:")
        print("  1. 100 RST пакетов исчерпывают глобальный лимит challenge ACK")
        print("  2. При поддельном SYN сервер хочет отправить challenge ACK")
        print("  3. Если лимит исчерпан → challenge ACK НЕ отправляется")
        print("  4. Атакующий определяет это по отсутствию прироста счётчика")
        print("\n  Таким образом, атакующий может угадать порт, просто")
        print("  подсчитывая полученные challenge ACK!")
        print("=" * 60)


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     OFF-PATH TCP EXPLOIT - СИМУЛЯЦИЯ (RFC 5961 уязвимость)    ║
    ║                                                               ║
    ║  Принцип: глобальный лимит 100 challenge ACK/сек создаёт      ║
    ║           измеримый побочный канал для угадывания портов.     ║
    ║                                                               ║
    ║  [!] Это учебная демонстрация, не выполняющая реальных атак   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Создаём уязвимый сервер
    server = VulnerableServer()
    
    # Создаём атакующего
    attacker = OffPathAttacker(server)
    
    # Демонстрация побочного канала
    attacker.demonstrate_side_channel()
    
    # Подбор порта (демонстрация с небольшим диапазоном)
    print("\n" + "=" * 60)
    print("ДЕМОНСТРАЦИЯ ПОДБОРА ПОРТА")
    print("=" * 60)
    
    # Создаём новый сервер для теста подбора
    server2 = VulnerableServer()
    attacker2 = OffPathAttacker(server2)
    
    # Случайный порт для подбора
    secret_port = random.randint(50000, 50010)
    secret_conn = Connection(
        src_ip = attacker2.target_ip, src_port = secret_port,
        dst_ip = attacker2.server_ip, dst_port = attacker2.server_port,
        seq_num = 1000, ack_num = 2000, window = 8192
    )
    server2.active_connections[secret_conn] = MutableConnection(secret_conn)
    
    print(f"\n[СЕРВЕР] Секретный порт клиента: {secret_port}")
    print(f"[СЕРВЕР] Атакующий НЕ знает этот порт и не видит трафик")
    
    # Подбираем порт
    found = attacker2.brute_force_port(range(50000, 50011))
    
    if found == secret_port:
        print(f"\n[✓] АТАКА УСПЕШНА! Порт {secret_port} угадан верно!")
    else:
        print(f"\n[✗] Ошибка: угадан {found}, ожидался {secret_port}")
    
    print("\n" + "=" * 60)
    print("ВЫВОДЫ (из текста):")
    print("1. Атака возможна без прослушивания трафика (off-path)")
    print("2. Глобальная переменная — источник утечки (side-channel)")
    print("3. RFC 5961 пытался повысить безопасность, но создал уязвимость")
    print("4. Аналогичная техника использовалась NSA в атаке Quantum")
    print("5. После получения порта атакующий так же подбирает SEQ и ACK")
    print("=" * 60)


if __name__ == "__main__":
    main()