#!/usr/bin/env python3
"""
Учебный сканер портов и fingerprinting
Реализует методы из описания: SYN, CONNECT, FIN, Xmas, определение ОС, баннер-грабинг
"""

import socket
import struct
import time
import sys
import threading
from typing import List, Tuple, Optional
from scapy.all import UDPDrain, sr1, IP, TCP, conf
from scapy.all import Ether, ARP, srp  # для локальной сети, не используется в основном коде

# Настройка Scapy для работы без лишнего вывода
conf.verb = 0

# Общие порты для быстрого сканирования
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

# Ассоциация портов с сервисами
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
}

# Типичные значения TTL для определения ОС
TTL_SIGNATURES = {
    64: "Linux / FreeBSD / Unix",
    128: "Windows",
    255: "Cisco / Solaris / AIX",
    60: "Некоторые Linux (короткий TTL)",
    32: "Некоторые embedded устройства"
}


class PortScanner:
    def __init__(self, target_ip: str, timeout: float = 2.0):
        self.target_ip = target_ip
        self.timeout = timeout
        
    def connect_scan(self, ports: List[int]) -> List[Tuple[int, bool, Optional[str]]]:
        """
        Метод CONNECT-сканирования (полное TCP-соединение)
        Заметен в логах, но работает без привилегий
        """
        print(f"[CONNECT] Сканирование {self.target_ip} (метод connect)")
        results = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    service = SERVICE_MAP.get(port, "unknown")
                    print(f"  [+] Порт {port} ОТКРЫТ ({service})")
                    results.append((port, True, service))
                else:
                    results.append((port, False, None))
                sock.close()
            except socket.error:
                results.append((port, False, None))
                
        return results
    
    def syn_scan(self, ports: List[int]) -> List[Tuple[int, bool, Optional[str]]]:
        """
        SYN-сканирование (полуоткрытое)
        ТРЕБУЕТ ПРАВ ROOT/ADMIN (сырые сокеты)
        Отправляет SYN, ждёт SYN-ACK, НЕ отправляет ACK (не завершает handshake)
        """
        print(f"[SYN] Полуоткрытое сканирование {self.target_ip} (требует root)")
        results = []
        
        for port in ports:
            # Формируем TCP-пакет с флагом SYN
            ip_pkt = IP(dst=self.target_ip)
            tcp_pkt = TCP(dport=port, flags="S")  # S = SYN
            pkt = ip_pkt / tcp_pkt
            
            # Отправляем и ждём ответ
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                # SYN-ACK означает, что порт открыт
                if tcp_layer.flags == 0x12:  # 0x12 = SYN+ACK
                    service = SERVICE_MAP.get(port, "unknown")
                    print(f"  [+] Порт {port} ОТКРЫТ ({service}) [SYN-ACK]")
                    results.append((port, True, service))
                # RST означает, что порт закрыт
                elif tcp_layer.flags == 0x14:  # 0x14 = RST+ACK
                    results.append((port, False, None))
                else:
                    results.append((port, False, None))
            else:
                # Нет ответа — вероятно, порт фильтруется
                results.append((port, False, None))
                
        return results
    
    def fin_scan(self, ports: List[int]) -> List[Tuple[int, bool, Optional[str]]]:
        """
        FIN-сканирование (обход некоторых stateless-брандмауэров)
        Отправляет FIN-пакет (обычно для закрытия соединения)
        Если порт закрыт: ответ RST
        Если порт открыт: молчание (по RFC 793)
        НЕ РАБОТАЕТ на Windows (всегда RST)
        """
        print(f"[FIN] FIN-сканирование {self.target_ip} (не работает на Windows)")
        results = []
        
        for port in ports:
            ip_pkt = IP(dst=self.target_ip)
            tcp_pkt = TCP(dport=port, flags="F")  # F = FIN
            pkt = ip_pkt / tcp_pkt
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                # Получили RST — порт закрыт
                if tcp_layer.flags == 0x14:  # RST+ACK или просто RST
                    results.append((port, False, None))
                else:
                    # Другой ответ — трактуем как открытый (нестандартно)
                    service = SERVICE_MAP.get(port, "unknown")
                    print(f"  [+] Порт {port} ВОЗМОЖНО ОТКРЫТ ({service}) [FIN без RST]")
                    results.append((port, True, service))
            else:
                # Нет ответа — по спецификации порт открыт
                service = SERVICE_MAP.get(port, "unknown")
                print(f"  [+] Порт {port} ВОЗМОЖНО ОТКРЫТ ({service}) [FIN без ответа]")
                results.append((port, True, service))
                
        return results
    
    def xmas_scan(self, ports: List[int]) -> List[Tuple[int, bool, Optional[str]]]:
        """
        Xmas-сканирование (одновременная установка FIN + PSH + URG)
        Как и FIN-сканирование, обходит некоторые брандмауэры
        Название — «сверкает, как рождественская ёлка»
        """
        print(f"[XMAS] Xmas-сканирование {self.target_ip} (FIN+PSH+URG)")
        results = []
        
        for port in ports:
            # Флаги: F (FIN) + P (PSH) + U (URG)
            ip_pkt = IP(dst=self.target_ip)
            tcp_pkt = TCP(dport=port, flags="FPU")  # FPU = FIN+PSH+URG
            pkt = ip_pkt / tcp_pkt
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x14:  # RST
                    results.append((port, False, None))
                else:
                    service = SERVICE_MAP.get(port, "unknown")
                    print(f"  [+] Порт {port} ВОЗМОЖНО ОТКРЫТ ({service})")
                    results.append((port, True, service))
            else:
                service = SERVICE_MAP.get(port, "unknown")
                print(f"  [+] Порт {port} ВОЗМОЖНО ОТКРЫТ ({service})")
                results.append((port, True, service))
                
        return results
    
    def grab_banner(self, port: int, timeout: float = 3.0) -> Optional[str]:
        """
        Баннер-грабинг: подключается к открытому порту и читает приветствие
        Полезно для определения версии сервиса и ОС
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.target_ip, port))
            
            # Для некоторых протоколов нужно отправить запрос
            banner = ""
            if port == 80 or port == 8080 or port == 8443:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 21:  # FTP
                pass  # просто читаем приветствие
            elif port == 25:  # SMTP
                sock.send(b"EHLO test\r\n")
            elif port == 22:  # SSH
                pass  # читаем версию SSH
            
            banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Обрезаем слишком длинные баннеры
            if len(banner) > 200:
                banner = banner[:200] + "..."
            return banner if banner else None
            
        except Exception:
            return None
    
    def detect_os_by_ttl(self, port: int = 80) -> Optional[str]:
        """
        Определение ОС по TTL ответного TCP-пакета
        Отправляем SYN на открытый порт и смотрим TTL
        """
        try:
            ip_pkt = IP(dst=self.target_ip)
            tcp_pkt = TCP(dport=port, flags="S")
            pkt = ip_pkt / tcp_pkt
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(IP):
                ttl = response.ttl
                # Корректируем TTL (мог уменьшиться на маршрутизаторах)
                # Для оценки используем ближайшее стандартное значение
                for std_ttl, os_name in TTL_SIGNATURES.items():
                    if abs(ttl - std_ttl) <= 5:  # допустимое отклонение
                        return f"{os_name} (TTL={ttl})"
                return f"Неизвестная ОС (TTL={ttl})"
            return None
        except Exception:
            return None
    
    def traceroute(self, max_hops: int = 30) -> List[str]:
        """
        Эмуляция traceroute: определение пути до целевого хоста
        Отправляет UDP-пакеты с увеличивающимся TTL
        """
        print(f"\n[TRACEROUTE] Маршрут до {self.target_ip}")
        route = []
        
        for ttl in range(1, max_hops + 1):
            # Создаём IP-пакет с заданным TTL
            ip_pkt = IP(dst=self.target_ip, ttl=ttl)
            # UDP на нестандартный порт (чтобы получить ICMP Time Exceeded)
            udp_pkt = UDPDrain(dport=33434 + ttl)
            pkt = ip_pkt / udp_pkt
            
            response = sr1(pkt, timeout=self.timeout, verbose=0)
            
            if response is None:
                route.append(f"{ttl}: * * *")
                continue
                
            # Определяем IP источника ответа
            if response.haslayer(IP):
                src_ip = response.src
                
                if src_ip == self.target_ip:
                    route.append(f"{ttl}: {src_ip} (ДОСТИГНУТ ЦЕЛЬ)")
                    break
                else:
                    route.append(f"{ttl}: {src_ip}")
            else:
                route.append(f"{ttl}: [не IP-ответ]")
                
        return route


def main():
    print("=" * 60)
    print("УЧЕБНЫЙ СКАНЕР ПОРТОВ И FINGERPRINTING")
    print("Реализует методы: CONNECT, SYN, FIN, Xmas, баннер-грабинг, traceroute")
    print("=" * 60)
    
    target = input("Введите IP-адрес или домен цели: ").strip()
    if not target:
        print("Ошибка: нужен IP-адрес")
        return
    
    # Разрешаем домен в IP
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Цель разрешена: {target_ip}\n")
    except socket.gaierror:
        print("Не удалось разрешить домен")
        return
    
    scanner = PortScanner(target_ip, timeout=2.0)
    
    # Выбор метода сканирования
    print("Доступные методы:")
    print("  1. CONNECT-сканирование (полное соединение, без прав)")
    print("  2. SYN-сканирование (полуоткрытое, ТРЕБУЕТ ROOT/ADMIN)")
    print("  3. FIN-сканирование (обход брандмауэров, не работает на Windows)")
    print("  4. Xmas-сканирование (FIN+PSH+URG)")
    print("  5. Комбинированное (SYN + баннеры + ОС + traceroute)")
    
    choice = input("\nВыберите метод (1-5): ").strip()
    
    # Список портов для сканирования
    use_all_ports = input("Сканировать все 65535 портов? (y/N): ").strip().lower() == 'y'
    if use_all_ports:
        ports = list(range(1, 65536))
        print("ВНИМАНИЕ: сканирование всех портов может занять очень много времени!")
        confirm = input("Продолжить? (y/N): ").strip().lower()
        if confirm != 'y':
            ports = COMMON_PORTS
    else:
        ports = COMMON_PORTS
    
    print(f"\nБудут проверены порты: {ports[:10]}... (всего {len(ports)} портов)\n")
    
    # Запуск выбранного метода
    results = []
    
    if choice == '1':
        results = scanner.connect_scan(ports)
    elif choice == '2':
        try:
            results = scanner.syn_scan(ports)
        except PermissionError:
            print("\n[ОШИБКА] SYN-сканирование требует прав root/администратора!")
            print("Попробуйте запустить программу с sudo (Linux/macOS) или от имени администратора (Windows)")
            return
    elif choice == '3':
        results = scanner.fin_scan(ports)
    elif choice == '4':
        results = scanner.xmas_scan(ports)
    elif choice == '5':
        # Комбинированный режим
        print("=== КОМБИНИРОВАННОЕ ИССЛЕДОВАНИЕ ===")
        try:
            results = scanner.syn_scan(ports)
        except PermissionError:
            print("SYN-скан не доступен (нужен root). Использую CONNECT-скан.")
            results = scanner.connect_scan(ports)
        
        # Собираем открытые порты
        open_ports = [p for p, is_open, _ in results if is_open]
        
        if open_ports:
            print(f"\n=== БАННЕР-ГРАББИНГ (открытые порты: {open_ports}) ===")
            for port in open_ports[:5]:  # не более 5 портов для баннеров
                banner = scanner.grab_banner(port)
                if banner:
                    print(f"  Порт {port}: {banner[:100]}")
                else:
                    print(f"  Порт {port}: баннер не получен")
            
            # Определение ОС
            print("\n=== ОПРЕДЕЛЕНИЕ ОС ПО TTL ===")
            os_info = scanner.detect_os_by_ttl(open_ports[0] if open_ports else 80)
            if os_info:
                print(f"  {os_info}")
            else:
                print("  Не удалось определить ОС")
        
        # Traceroute
        route = scanner.traceroute(max_hops=15)
        print("\n=== TRACEROUTE ===")
        for hop in route:
            print(f"  {hop}")
        
        print("\nКомбинированное сканирование завершено.")
        return
    
    # Вывод результатов для простых методов
    print("\n=== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ===")
    open_ports_found = [p for p, is_open, _ in results if is_open]
    
    if open_ports_found:
        print(f"Найдено открытых портов: {len(open_ports_found)}")
        for port, _, service in results:
            if port in open_ports_found:
                banner = scanner.grab_banner(port) if choice != '2' else None
                banner_str = f" [{banner[:80]}]" if banner else ""
                print(f"  {port}: {service}{banner_str}")
    else:
        print("Открытых портов не найдено (или все фильтруются брандмауэром)")
    
    # Дополнительно: определение ОС (если есть открытый порт)
    if open_ports_found and choice in ['1', '2']:
        print("\n=== ОПРЕДЕЛЕНИЕ ОС ===")
        os_info = scanner.detect_os_by_ttl(open_ports_found[0])
        if os_info:
            print(f"  {os_info}")


if __name__ == "__main__":
    # Проверка наличия scapy
    try:
        from scapy.all import IP, TCP, sr1
    except ImportError:
        print("Ошибка: требуется установить scapy")
        print("Установка: pip install scapy")
        print("На Windows可能需要 установить Npcap (https://npcap.com)")
        sys.exit(1)
    
    main()