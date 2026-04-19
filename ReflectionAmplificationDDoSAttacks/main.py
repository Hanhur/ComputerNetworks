#!/usr/bin/env python3
"""
Симуляция UDP Reflection + Amplification DDoS-атак
Только для образовательных целей!
"""

import socket
import random
import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Tuple

# ========== Конфигурация протоколов с коэффициентами усиления ==========
@dataclass
class ProtocolAmplifier:
    """Модель публичного UDP-сервиса, который можно использовать как усилитель"""
    name: str
    port: int
    request_size: int          # типичный размер запроса (байт)
    response_size: int         # типичный размер ответа (байт)
    amplification_factor: float # коэффициент усиления
    
    @property
    def byte_amplification(self) -> float:
        return self.response_size / self.request_size

# Известные протоколы с усилением (из текста)
AMPLIFIER_PROTOCOLS = [
    ProtocolAmplifier("DNS (ANY)", 53, 30, 1800, 60.0),
    ProtocolAmplifier("DNSSEC", 53, 50, 9000, 180.0),
    ProtocolAmplifier("NTP (monlist)", 123, 234, 4680, 20.0),
    ProtocolAmplifier("memcached", 11211, 20, 1024000, 51200.0),  # >50k
    ProtocolAmplifier("CLDAP", 389, 50, 3000, 60.0),
    ProtocolAmplifier("SSDP", 1900, 30, 1200, 40.0),
    ProtocolAmplifier("QOTD (Quote of the Day)", 17, 20, 500, 25.0),
]

# ========== Симулятор уязвимого сервера (для локального тестирования) ==========
class VulnerableUDPServer:
    """Имитация реального UDP-сервера, который отвечает на поддельные запросы"""
    
    def __init__(self, protocol: ProtocolAmplifier, bind_ip: str = "127.0.0.1"):
        self.protocol = protocol
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((bind_ip, protocol.port))
        self.running = True
        self.request_count = 0
        self.response_count = 0
        
    def start(self):
        """Запуск сервера в отдельном потоке"""
        def handle():
            print(f"[СЕРВЕР] Запущен {self.protocol.name} на порту {self.protocol.port}")
            print(f"         Коэффициент усиления: {self.protocol.amplification_factor:.1f}x")
            while self.running:
                try:
                    self.sock.settimeout(0.5)
                    data, addr = self.sock.recvfrom(4096)
                    self.request_count += 1
                    
                    # Имитация ответа с усилением
                    response = self._generate_response(data)
                    self.sock.sendto(response, addr)
                    self.response_count += 1
                    
                    if self.request_count % 10 == 0:
                        print(f"[{self.protocol.name}] Запросов: {self.request_count}, "
                              f"Ответов: {self.response_count}")
                              
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Ошибка: {e}")
                    
        self.thread = threading.Thread(target = handle, daemon = True)
        self.thread.start()
        
    def _generate_response(self, request: bytes) -> bytes:
        """Генерация ответа с учётом коэффициента усиления"""
        requested_size = len(request)
        response_size = min(
            int(requested_size * self.protocol.amplification_factor),
            self.protocol.response_size
        )
        # Заполняем фиктивными данными
        return b'X' * response_size
    
    def stop(self):
        self.running = False
        self.sock.close()
        
    def get_stats(self) -> Tuple[int, int]:
        return self.request_count, self.response_count


# ========== Атакующий (отражение + усиление) ==========
class ReflectionAmplificationAttacker:
    """
    Симулирует злоумышленника, который:
    1. Подменяет source IP на IP жертвы
    2. Отправляет маленькие запросы публичным UDP-серверам
    3. Серверы отвечают жертве большими ответами
    """
    
    def __init__(self, victim_ip: str):
        self.victim_ip = victim_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.stats = defaultdict(lambda: {"requests": 0, "responses": 0})
        
    def _spoofed_send(self, target_ip: str, target_port: int, payload: bytes):
        """
        Отправка пакета с поддельным адресом отправителя (жертва)
        В реальной жизни требует raw-сокетов или специальных библиотек (scapy)
        Здесь симуляция: просто печатаем, что отправили бы
        """
        # В реальном коде с raw-сокетами: 
        # packet = IP(src=self.victim_ip, dst=target_ip)/UDP(sport=random, dport=target_port)/payload
        # send(packet)
        
        print(f"  [СПУФИНГ] Отправка {len(payload)} байт от {self.victim_ip} -> {target_ip}:{target_port}")
        
    def launch_attack(self, amplifiers: List[Tuple[str, ProtocolAmplifier]], 
                      duration_sec: int = 10, rate_per_sec: int = 100):
        """
        Запуск симулированной атаки с отражением и усилением
        
        :param amplifiers: список (IP_сервера, протокол)
        :param duration_sec: длительность атаки
        :param rate_per_sec: запросов в секунду
        """
        print(f"\n{'=' * 60}")
        print(f"🚨 СИМУЛЯЦИЯ АТАКИ: Reflection + Amplification")
        print(f"   Жертва: {self.victim_ip}")
        print(f"   Длительность: {duration_sec} сек")
        print(f"   Темп: {rate_per_sec} запросов/сек")
        print(f"   Серверов-усилителей: {len(amplifiers)}")
        print(f"{'=' * 60}\n")
        
        end_time = time.time() + duration_sec
        total_requests = 0
        total_response_bytes = 0
        
        # Статистика по протоколам
        proto_stats = defaultdict(lambda: {"requests": 0, "bytes_sent_to_victim": 0})
        
        while time.time() < end_time:
            # Выбираем случайный усилитель
            amp_ip, protocol = random.choice(amplifiers)
            
            # Формируем маленький запрос
            request = b'Q' * protocol.request_size
            
            # Симуляция отправки поддельного пакета
            self._spoofed_send(amp_ip, protocol.port, request)
            total_requests += 1
            
            # Сервер ответит жертве с усилением
            response_size = int(protocol.request_size * protocol.amplification_factor)
            total_response_bytes += response_size
            
            proto_stats[protocol.name]["requests"] += 1
            proto_stats[protocol.name]["bytes_sent_to_victim"] += response_size
            
            # Контроль скорости
            time.sleep(1.0 / rate_per_sec)
            
        # Итоги атаки
        print(f"\n{'=' * 60}")
        print("📊 РЕЗУЛЬТАТЫ АТАКИ")
        print(f"   Всего поддельных запросов отправлено: {total_requests}")
        print(f"   Объём ответного трафика, направленного жертве: "f"{total_response_bytes / 1024 / 1024:.2f} МБ")
        print(f"   Средний коэффициент усиления: "f"{total_response_bytes / (total_requests * 20):.1f}x (примерно)")
        print(f"\n   Детализация по протоколам:")
        for name, stats in sorted(proto_stats.items(), key = lambda x: -x[1]["bytes_sent_to_victim"]):
            print(f"     - {name}: {stats['requests']} запросов, "f"{stats['bytes_sent_to_victim'] / 1024:.1f} КБ ответов")
        print(f"{'=' * 60}\n")


# ========== Симулятор жертвы (принимает усиленный трафик) ==========
class VictimSimulator:
    """Симулирует компьютер жертвы, принимающий лавину UDP-пакетов"""
    
    def __init__(self, ip: str = "127.0.0.100", port_range_start: int = 10000):
        self.ip = ip
        self.port_range_start = port_range_start
        self.packet_count = 0
        self.byte_count = 0
        self.sock = None
        self.running = False
        
    def start_listening(self, num_ports: int = 10):
        """Слушает несколько UDP-портов (симуляция жертвы)"""
        self.sockets = []
        for i in range(num_ports):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            port = self.port_range_start + i
            try:
                sock.bind((self.ip, port))
                self.sockets.append(sock)
            except Exception as e:
                print(f"Не удалось bind на {self.ip}:{port} - {e}")
                
        self.running = True
        
        def receive_loop(sock):
            while self.running:
                try:
                    sock.settimeout(0.1)
                    data, addr = sock.recvfrom(65535)
                    self.packet_count += 1
                    self.byte_count += len(data)
                    if self.packet_count % 100 == 0:
                        print(f"[ЖЕРТВА] Получено {self.packet_count} пакетов, "f"{self.byte_count / 1024:.1f} КБ")
                except socket.timeout:
                    continue
                    
        self.threads = []
        for sock in self.sockets:
            t = threading.Thread(target = receive_loop, args = (sock,), daemon = True)
            t.start()
            self.threads.append(t)
            
        print(f"[ЖЕРТВА] Слушает на {self.ip}, порты {self.port_range_start}..{self.port_range_start + num_ports - 1}")
        
    def stop_listening(self):
        self.running = False
        for sock in self.sockets:
            sock.close()
            
    def get_stats(self):
        return self.packet_count, self.byte_count


# ========== Главная демонстрация ==========
def main():
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     UDP REFLECTION + AMPLIFICATION DDoS - СИМУЛЯЦИЯ          ║
    ║                    ТОЛЬКО ДЛЯ ОБУЧЕНИЯ                       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # 1. Запускаем симулированные "уязвимые" UDP-серверы (усилители)
    print("[1] Запуск симулированных публичных UDP-серверов (усилителей)...")
    servers = []
    for proto in AMPLIFIER_PROTOCOLS[:4]:  # берём первые 4 для демо
        server = VulnerableUDPServer(proto, bind_ip="127.0.0.1")
        server.start()
        servers.append(server)
    time.sleep(1)
    
    # 2. Список доступных усилителей (в реальности это миллионы серверов в интернете)
    amplifiers = [
        ("127.0.0.1", AMPLIFIER_PROTOCOLS[0]),  # DNS
        ("127.0.0.1", AMPLIFIER_PROTOCOLS[1]),  # DNSSEC
        ("127.0.0.1", AMPLIFIER_PROTOCOLS[2]),  # NTP
        ("127.0.0.1", AMPLIFIER_PROTOCOLS[3]),  # memcached
    ]
    
    # 3. Запускаем жертву
    print("\n[2] Запуск симуляции жертвы...")
    victim = VictimSimulator(ip = "127.0.0.100", port_range_start = 20000)
    victim.start_listening(num_ports = 5)
    time.sleep(1)
    
    # 4. Атака
    print("\n[3] Запуск атаки с отражением и усилением...")
    attacker = ReflectionAmplificationAttacker(victim_ip = victim.ip)
    
    input("\nНажмите Enter для начала атаки...")
    
    # Короткая атака для демонстрации
    attacker.launch_attack(amplifiers, duration_sec = 8, rate_per_sec = 50)
    
    # 5. Сбор статистики с жертвы
    time.sleep(2)
    victim_packets, victim_bytes = victim.get_stats()
    
    print(f"\n{'=' * 60}")
    print("📋 ИТОГОВАЯ СТАТИСТИКА ЖЕРТВЫ:")
    print(f"   Получено UDP-пакетов: {victim_packets}")
    print(f"   Получено данных: {victim_bytes / 1024:.2f} КБ")
    print(f"{'=' * 60}")
    
    # 6. Остановка серверов
    print("\n[4] Остановка серверов...")
    for server in servers:
        server.stop()
    victim.stop_listening()
    
    print("\n✅ Симуляция завершена.")
    print("\n💡 Пояснение: Реальная атака использовала бы тысячи серверов-усилителей,")
    print("   и трафик измерялся бы в Гбит/с или Тбит/с, как в тексте (1.7 Тбит/с на memcached).")


if __name__ == "__main__":
    main()