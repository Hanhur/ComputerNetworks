#!/usr/bin/env python3
"""
Учебная демонстрация этапов сетевых атак (работает на Windows/Linux)
Только для изолированной тестовой среды!
Версия без обязательной зависимости от Npcap
"""

import socket
import random
import time
import threading
from datetime import datetime

# Попытка импорта Scapy (опционально для расширенных функций)
try:
    from scapy.all import IP, TCP, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[Предупреждение] Scapy не установлен. Установите: pip install scapy")
    print("Без Scapy некоторые функции будут работать в эмуляционном режиме.\n")


# ============================================================
# 1. РАЗВЕДКА (RECONNAISSANCE) - полностью рабочий вариант
# ============================================================
class NetworkReconnaissance:
    """Сбор информации о сети - первый шаг злоумышленника"""
    
    @staticmethod
    def port_scan(ip="127.0.0.1", ports=None):
        """TCP-сканирование портов с использованием socket"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 8080, 3306, 3389]
        
        print(f"\n[Разведка] Сканирование портов {ip}...")
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    print(f"  [+] Порт {port} ОТКРЫТ")
                sock.close()
            except Exception as e:
                pass
        
        print(f"  Найдено открытых портов: {len(open_ports)}")
        return open_ports
    
    @staticmethod
    def dns_lookup(hostname):
        """DNS-разведка - получение IP адресов"""
        print(f"\n[Разведка] DNS-запрос для {hostname}...")
        try:
            ip = socket.gethostbyname(hostname)
            print(f"  {hostname} -> {ip}")
            return ip
        except:
            print(f"  Не удалось разрешить {hostname}")
            return None
    
    @staticmethod
    def service_detection(ip, port):
        """Попытка определить службу по баннеру"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(256).decode('utf-8', errors='ignore')
            sock.close()
            if banner:
                print(f"  [{ip}:{port}] Баннер: {banner[:100]}")
            return banner
        except:
            return None


# ============================================================
# 2. ПРОСЛУШИВАНИЕ (SNIFFING) - сокетный вариант
# ============================================================
class NetworkSniffer:
    """Перехват сетевого трафика (сырые сокеты)"""
    
    def __init__(self):
        self.captured_packets = []
        
    def create_raw_socket(self):
        """Создание сырого сокета для прослушивания"""
        try:
            # Windows требует административных прав
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.bind(('0.0.0.0', 0))
            # Включаем смешанный режим (требует прав)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            return sock
        except Exception as e:
            print(f"  Не удалось создать raw-сокет (требуются права администратора): {e}")
            return None
    
    def parse_ip_header(self, data):
        """Парсинг IP-заголовка для извлечения информации"""
        if len(data) < 20:
            return None
        
        version_ihl = data[0]
        ihl = version_ihl & 0x0F
        ip_header_len = ihl * 4
        
        protocol = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        
        return {
            'src': src_ip,
            'dst': dst_ip,
            'proto': protocol,
            'header_len': ip_header_len
        }
    
    def start_sniffing_emulated(self, count=5):
        """Эмулированный режим прослушивания (без прав администратора)"""
        print(f"\n[Прослушивание - ЭМУЛЯЦИЯ] Создание тестового трафика...")
        
        # Создаём тестовые пакеты для демонстрации
        test_packets = [
            {"src": "192.168.1.100", "dst": "8.8.8.8", "proto": 6, "info": "TCP SYN порт 443"},
            {"src": "8.8.8.8", "dst": "192.168.1.100", "proto": 6, "info": "TCP SYN-ACK порт 443"},
            {"src": "192.168.1.100", "dst": "192.168.1.1", "proto": 17, "info": "DNS запрос google.com"},
            {"src": "192.168.1.1", "dst": "192.168.1.100", "proto": 17, "info": "DNS ответ 8.8.8.8"},
            {"src": "192.168.1.100", "dst": "93.184.216.34", "proto": 6, "info": "HTTP GET /"},
        ]
        
        for i, pkt in enumerate(test_packets[:count]):
            time.sleep(1)
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(pkt['proto'], "UNKNOWN")
            print(f"  [{i+1}] {pkt['src']} -> {pkt['dst']} ({proto_name}) {pkt['info']}")
            self.captured_packets.append(pkt)
        
        print(f"  Перехвачено {len(self.captured_packets)} пакетов (эмуляция)")
        print("  Примечание: для реального прослушивания запустите с правами администратора")
        return self.captured_packets
    
    def start_sniffing(self, count=5):
        """Запуск перехвата (если есть права)"""
        print(f"\n[Прослушивание] Запуск перехвата...")
        
        sock = self.create_raw_socket()
        if sock is None:
            return self.start_sniffing_emulated(count)
        
        print("  Реальный режим прослушивания (нажмите Ctrl+C для остановки)")
        captured = 0
        try:
            for i in range(count):
                packet_data, addr = sock.recvfrom(65535)
                ip_header = self.parse_ip_header(packet_data)
                if ip_header:
                    proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(ip_header['proto'], str(ip_header['proto']))
                    print(f"  [{i+1}] {ip_header['src']} -> {ip_header['dst']} ({proto_name})")
                    captured += 1
        except KeyboardInterrupt:
            pass
        finally:
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
        
        return captured


# ============================================================
# 3. ПОДМЕНА ДАННЫХ (SPOOFING)
# ============================================================
class SpoofingAttack:
    """Выдача себя за другого узла"""
    
    @staticmethod
    def tcp_syn_spoof_emulated(src_ip, dst_ip, dst_port):
        """Эмулированная версия спуфинга"""
        print(f"\n[Подмена - ЭМУЛЯЦИЯ] TCP SYN от имени {src_ip} -> {dst_ip}:{dst_port}")
        print("  [Демонстрация концепции]")
        print(f"  1. Отправлен подложный SYN-пакет с src={src_ip}")
        print(f"  2. Сервер ответит на {src_ip} (не на злоумышленника!)")
        print("  3. Злоумышленник не увидит SYN/ACK, если не находится в том же сегменте сети")
        print("  => Классическая проблема TCP-спуфинга")
        return True
    
    @staticmethod
    def arp_spoof_emulated(target_ip, gateway_ip):
        """Эмулированная версия ARP-спуфинга"""
        print(f"\n[Подмена - ЭМУЛЯЦИЯ] ARP-spoof: между {target_ip} и {gateway_ip}")
        print(f"  Злоумышленник отправляет поддельные ARP-ответы:")
        print(f"  - Жертве ({target_ip}): 'шлюз {gateway_ip} = MAC злоумышленника'")
        print(f"  - Шлюзу ({gateway_ip}): '{target_ip} = MAC злоумышленника'")
        print("  Результат: весь трафик между жертвой и шлюзом идёт через злоумышленника")
        print("  Нарушен принцип полной опосредованности")
        return True
    
    @staticmethod
    def run_spoofing_demo():
        """Демонстрация концепции подмены"""
        print("\n" + "="*60)
        print("КОНЦЕПЦИЯ ПОДМЕНЫ ДАННЫХ (SPOOFING)")
        print("="*60)
        
        SpoofingAttack.tcp_syn_spoof_emulated("1.2.3.4", "192.168.1.10", 80)
        print()
        SpoofingAttack.arp_spoof_emulated("192.168.1.10", "192.168.1.1")
        
        if SCAPY_AVAILABLE:
            print("\n  [Scapy обнаружен] Для реальной отправки пакетов:")
            print("  - Установите Npcap с сайта https://npcap.com")
            print("  - Запустите скрипт с правами администратора")


# ============================================================
# 4. НАРУШЕНИЕ РАБОТЫ (DISRUPTION / DoS)
# ============================================================
class DisruptionAttack:
    """Атаки на доступность"""
    
    @staticmethod
    def syn_flood_emulated(target_ip, target_port, count=100):
        """Эмулированная SYN-флуд атака"""
        print(f"\n[DoS - ЭМУЛЯЦИЯ] SYN-флуд на {target_ip}:{target_port}")
        print(f"  Отправка {count} поддельных SYN-пакетов...")
        
        for i in range(count):
            if i % 20 == 0:
                spoofed_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
                print(f"  [{i}/{count}] SYN от {spoofed_ip} -> {target_ip}:{target_port}")
            time.sleep(0.01)
        
        print(f"  Результат: таблица соединений целевого сервера переполнена")
        print("  Нарушен принцип минимизации общих механизмов (недостаточная изоляция)")
        return True
    
    @staticmethod
    def http_flood_emulated(target_url, count=50):
        """Эмулированная HTTP-флуд атака"""
        print(f"\n[DoS - ЭМУЛЯЦИЯ] HTTP-флуд на {target_url}")
        print(f"  Отправка {count} запросов...")
        
        for i in range(count):
            print(f"  [{i+1}/{count}] GET / HTTP/1.1")
            time.sleep(0.01)
        
        print("  Результат: перегрузка CPU и памяти веб-сервера")
        return True
    
    @staticmethod
    def run_dos_demo():
        """Демонстрация DoS атак"""
        print("\n" + "="*60)
        print("ДЕМОНСТРАЦИЯ DoS АТАК")
        print("="*60)
        
        DisruptionAttack.syn_flood_emulated("192.168.1.100", 80, 50)
        DisruptionAttack.http_flood_emulated("http://target-site.com", 30)


# ============================================================
# КОМБИНИРОВАННАЯ АТАКА (пример из текста)
# ============================================================
class CombinedAttack:
    """
    Комбинация: разведка -> DoS -> подмена
    (по мотивам атаки на Суперкомпьютерный центр Сан-Диего)
    """
    
    @staticmethod
    def demo_san_diego_style():
        """Демонстрация комбинированной атаки"""
        print("\n" + "="*70)
        print("КОМБИНИРОВАННАЯ АТАКА (по мотивам атаки на Суперкомпьютерный центр Сан-Диего)")
        print("="*70)
        
        # Шаг 1: Разведка
        print("\n[ШАГ 1] РАЗВЕДКА")
        print("  Злоумышленник выясняет:")
        print("  - Жертва (пользователь) доверяет определённому серверу")
        print("  - Жертва автоматически принимает запросы от этого сервера без проверки")
        print("  - IP-адрес сервера: 203.0.113.10")
        
        # Шаг 2: Прослушивание
        print("\n[ШАГ 2] ПРОСЛУШИВАНИЕ")
        print("  Злоумышленник перехватывает трафик и подтверждает:")
        print("  - Жертва не использует шифрование/аутентификацию")
        print("  - Любой пакет с src=203.0.113.10 принимается как легитимный")
        
        # Шаг 3: DoS на настоящий сервер
        print("\n[ШАГ 3] DoS-АТАКА НА НАСТОЯЩИЙ СЕРВЕР")
        print("  Злоумышленник выводит из строя легитимный сервер 203.0.113.10")
        DisruptionAttack.syn_flood_emulated("203.0.113.10", 443, 100)
        print("  Настоящий сервер перестал отвечать")
        
        # Шаг 4: Подмена
        print("\n[ШАГ 4] ПОДМЕНА ЗАПРОСОВ")
        print("  Злоумышленник отправляет подложные запросы жертве")
        print("  (с поддельным src-адресом 203.0.113.10)")
        SpoofingAttack.tcp_syn_spoof_emulated("203.0.113.10", "192.168.1.100", 22)
        print("  Жертва принимает запрос, думая, что он от доверенного сервера")
        
        print("\n" + "="*70)
        print("ИТОГ: АТАКА УСПЕШНА")
        print("="*70)
        print("""  Именно так была осуществлена одна из самых известных атак 
  в истории интернета. Злоумышленник получил несанкционированный 
  доступ к системе жертвы, комбинируя:
  - Разведку (сбор информации о доверительных отношениях)
  - Прослушивание (подтверждение уязвимости)
  - DoS (выведение из строя настоящего сервера)
  - Спуфинг (имитация доверенного сервера)
  
  Нарушенные принципы безопасности:
  ✗ Минимизация полномочий
  ✗ Полная опосредованность  
  ✗ Минимизация общих механизмов
        """)


# ============================================================
# ОСНОВНАЯ ПРОГРАММА
# ============================================================
def print_banner():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║     УЧЕБНАЯ ДЕМОНСТРАЦИЯ ЭТАПОВ СЕТЕВЫХ АТАК                  ║
    ║     Основано на тексте о безопасности систем                  ║
    ║     [ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ]                        ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

def main():
    print_banner()
    
    print("\nВыберите демонстрацию:")
    print("┌─────────────────────────────────────────────────────────┐")
    print("│ 1 - РАЗВЕДКА    - сканирование портов, DNS запросы      │")
    print("│ 2 - ПРОСЛУШИВАНИЕ - перехват и анализ трафика           │")
    print("│ 3 - ПОДМЕНА     - спуфинг, ARP-атаки (концепция)        │")
    print("│ 4 - DoS         - отказ в обслуживании (концепция)      │")
    print("│ 5 - КОМБО       - атака как на Суперкомпьютерный центр  │")
    print("│ 0 - Выход                                               │")
    print("└─────────────────────────────────────────────────────────┘")
    
    choice = input("\nВаш выбор: ").strip()
    
    if choice == "1":
        recon = NetworkReconnaissance()
        print("\n--- ДЕМОНСТРАЦИЯ РАЗВЕДКИ ---")
        recon.port_scan("127.0.0.1")
        recon.dns_lookup("google.com")
        recon.dns_lookup("github.com")
        
    elif choice == "2":
        print("\n--- ДЕМОНСТРАЦИЯ ПРОСЛУШИВАНИЯ ---")
        sniffer = NetworkSniffer()
        sniffer.start_sniffing(count=5)
        
    elif choice == "3":
        SpoofingAttack.run_spoofing_demo()
        
    elif choice == "4":
        DisruptionAttack.run_dos_demo()
        
    elif choice == "5":
        CombinedAttack.demo_san_diego_style()
        
    else:
        print("Выход.")
        return
    
    print("\n" + "="*60)
    input("Нажмите Enter для выхода...")


if __name__ == "__main__":
    main()