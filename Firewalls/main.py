#!/usr/bin/env python3
"""
Симулятор брандмауэра (Firewall Simulator)
Демонстрирует принципы: packet filter, stateful inspection, application-level gateway, DMZ
"""

import time
import re
from dataclasses import dataclass
from typing import Dict, Set, List, Optional, Tuple
from enum import Enum
from collections import defaultdict


class PacketDirection(Enum):
    INBOUND = "входящий"
    OUTBOUND = "исходящий"


class Action(Enum):
    ALLOW = "✅ ПРОПУЩЕН"
    DROP = "❌ ОТБРОШЕН"
    REJECT = "🚫 ОТКЛОНЕН (с уведомлением)"


@dataclass
class Packet:
    """Сетевой пакет"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP
    payload: str = ""
    flags: Set[str] = None  # SYN, ACK, FIN, RST
    
    def __post_init__(self):
        if self.flags is None:
            self.flags = set()


@dataclass
class Connection:
    """Отслеживание состояния соединения (stateful)"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    established: bool = False
    direction: PacketDirection = None


class ApplicationLevelGateway:
    """Шлюз прикладного уровня - проверяет содержимое пакетов"""
    
    @staticmethod
    def is_http_web_browsing(payload: str) -> bool:
        """HTTP-запрос для веб-сёрфинга (GET, POST к обычным URL)"""
        web_patterns = [r'GET /', r'POST /', r'Host:', r'User-Agent:']
        file_sharing_patterns = [r'GET /announce\?info_hash=', r'tracker', r'BitTorrent', r'ed2k://', r'magnet:']
        
        if any(p in payload for p in file_sharing_patterns):
            return False
        return any(p in payload for p in web_patterns)
    
    @staticmethod
    def contains_confidential(payload: str) -> bool:
        """Обнаружение секретных документов в исходящем трафике"""
        keywords = ['секретно', 'confidential', 'пароль', 'password', 'коммерческая тайна', 'classified']
        return any(kw.lower() in payload.lower() for kw in keywords)
    
    @staticmethod
    def is_email(payload: str) -> bool:
        """Проверка, является ли трафик почтовым (SMTP)"""
        return 'MAIL FROM:' in payload or 'RCPT TO:' in payload or 'Subject:' in payload


class Firewall:
    """Основной класс брандмауэра"""
    
    def __init__(self, name="Corporate Firewall"):
        self.name = name
        self.rules: List[dict] = []
        self.connections: Dict[Tuple[str, int, str, int], Connection] = {}
        self.dmz_zone: Set[str] = set()  # IP-адреса в DMZ
        self.internal_network: Set[str] = set()  # Внутренние IP
        self.blacklisted_ips: Set[str] = set()
        self.whitelisted_ips: Set[str] = set()
        
        # Счётчики статистики
        self.stats = {
            'packets_processed': 0,
            'allowed': 0,
            'dropped': 0,
            'spoofing_detected': 0
        }
        
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Загрузка правил по умолчанию из текста"""
        # 1. Блокировка порта 79 (Finger - использовался в атаке 1988 года)
        self.add_rule(port = 79, action = Action.DROP, direction = PacketDirection.INBOUND, reason = "Порт Finger (исторически опасен, атака 1988)")
        
        # 2. Разрешить HTTP/HTTPS для всех
        self.add_rule(port = 80, action = Action.ALLOW, direction = PacketDirection.INBOUND, condition = "dmz_only", reason = "HTTP - только для DMZ")
        self.add_rule(port = 443, action = Action.ALLOW, direction = PacketDirection.INBOUND, condition = "dmz_only", reason = "HTTPS - только для DMZ")
        
        # 3. Исходящий HTTP разрешён всем (веб-сёрфинг)
        self.add_rule(port = 80, action = Action.ALLOW, direction = PacketDirection.OUTBOUND, reason = "Исходящий веб-трафик")
        self.add_rule(port = 443, action = Action.ALLOW, direction = PacketDirection.OUTBOUND, reason = "Исходящий HTTPS")
        
        # 4. Почта (SMTP) - только исходящая
        self.add_rule(port = 25, action = Action.ALLOW, direction = PacketDirection.OUTBOUND, reason = "Исходящая почта (SMTP)")
        self.add_rule(port = 25, action = Action.DROP, direction = PacketDirection.INBOUND, reason = "Входящий SMTP заблокирован (используйте почтовый шлюз)")
        
        # 5. SSH - только для администраторов (имитация)
        self.add_rule(port = 22, action = Action.ALLOW, direction = PacketDirection.INBOUND, condition = "internal_only", reason = "SSH только из внутренней сети")
        
        # 6. Блокировка известных P2P портов
        for p2p_port in [6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889]:
            self.add_rule(port = p2p_port, action = Action.DROP, direction = PacketDirection.INBOUND, reason = "Блокировка BitTorrent трафика")
            self.add_rule(port = p2p_port, action = Action.DROP, direction = PacketDirection.OUTBOUND, reason = "Блокировка BitTorrent трафика")
    
    def add_rule(self, port: int = None, src_ip: str = None, dst_ip: str = None, action: Action = Action.ALLOW, direction: PacketDirection = None, condition: str = None, reason: str = ""):
        """Добавление правила фильтрации"""
        rule = {
            'port': port,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'action': action,
            'direction': direction,
            'condition': condition,
            'reason': reason,
            'id': len(self.rules)
        }
        self.rules.append(rule)
    
    def set_dmz(self, ips: Set[str]):
        """Настройка DMZ (демилитаризованной зоны)"""
        self.dmz_zone = ips
        print(f"🌐 DMZ настроена: {ips}")
    
    def set_internal_network(self, ips: Set[str]):
        """Настройка внутренней сети"""
        self.internal_network = ips
        print(f"🏢 Внутренняя сеть: {ips}")
    
    def detect_spoofing(self, packet: Packet, direction: PacketDirection) -> bool:
        """
        Обнаружение фальсификации IP-адреса (спуфинга)
        Входящий пакет с внутренним IP отправителя из внешней сети = подозрительно
        """
        if direction == PacketDirection.INBOUND:
            # Пакет извне не может иметь внутренний IP отправителя
            if packet.src_ip in self.internal_network:
                self.stats['spoofing_detected'] += 1
                print(f"⚠️ ОБНАРУЖЕН СПУФИНГ: {packet.src_ip} выдает себя за внутренний адрес!")
                return True
        else:
            # Исходящий пакет не может иметь внешний IP отправителя
            if packet.src_ip not in self.internal_network and packet.src_ip not in self.dmz_zone:
                if packet.src_ip != "0.0.0.0":  # NAT-случаи
                    print(f"⚠️ ПОДОЗРИТЕЛЬНЫЙ ИСХОДЯЩИЙ ПАКЕТ: src={packet.src_ip}")
        return False
    
    def check_stateful(self, packet: Packet, direction: PacketDirection) -> Tuple[bool, str]:
        """
        Stateful inspection: проверка состояния соединения
        Разрешает ответные пакеты только если соединение было инициировано изнутри
        """
        # Ключ соединения (симметричный)
        conn_key = (packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port)
        rev_key = (packet.dst_ip, packet.dst_port, packet.src_ip, packet.src_port)
        
        # SYN-пакет = попытка установить соединение
        if 'SYN' in packet.flags and 'ACK' not in packet.flags:
            if direction == PacketDirection.OUTBOUND:
                # Исходящее соединение - разрешаем и запоминаем
                self.connections[conn_key] = Connection(
                    src_ip=packet.src_ip, dst_ip=packet.dst_ip,
                    src_port=packet.src_port, dst_port=packet.dst_port,
                    established=False, direction=direction
                )
                return True, "Новое исходящее соединение (SYN)"
            else:
                # Входящий SYN без предварительного исходящего = подозрительно
                return False, "Несанкционированная попытка установки входящего соединения"
        
        # Проверка существующего соединения
        if conn_key in self.connections:
            conn = self.connections[conn_key]
            if 'ACK' in packet.flags or 'SYN' in packet.flags:
                conn.established = True
            return True, f"Разрешён по stateful-таблице (соединение {conn.direction.value})"
        
        if rev_key in self.connections:
            conn = self.connections[rev_key]
            # Ответный пакет (dst/src поменялись местами)
            if conn.established or 'RST' in packet.flags or 'FIN' in packet.flags:
                return True, f"Ответный пакет по установленному соединению ({conn.direction.value})"
        
        return None, "Нет состояния соединения"
    
    def check_application_layer(self, packet: Packet, direction: PacketDirection) -> Tuple[bool, str]:
        """Шлюз прикладного уровня - проверка содержимого"""
        if not packet.payload:
            return True, "Нет данных прикладного уровня"
        
        # Исходящий трафик: проверка на утечку секретных документов
        if direction == PacketDirection.OUTBOUND:
            if ApplicationLevelGateway.contains_confidential(packet.payload):
                return False, "⚠️ ОБНАРУЖЕНА ПОПЫТКА УТЕЧКИ СЕКРЕТНЫХ ДАННЫХ!"
            
            # Проверка P2P-файлообмена через HTTP
            if packet.dst_port == 80:
                if not ApplicationLevelGateway.is_http_web_browsing(packet.payload):
                    return False, "Обнаружен P2P-файлообмен (запрещён политикой)"
        
        return True, "Прикладной уровень OK"
    
    def process_packet(self, packet: Packet, direction: PacketDirection) -> Action:
        """Основная функция обработки пакета"""
        self.stats['packets_processed'] += 1
        
        print(f"\n📦 Пакет: {packet.src_ip}:{packet.src_port} → {packet.dst_ip}:{packet.dst_port}")
        print(f"   Направление: {direction.value}, Протокол: {packet.protocol}, Флаги: {packet.flags}")
        
        # 1. Проверка спуфинга
        if self.detect_spoofing(packet, direction):
            self.stats['dropped'] += 1
            return Action.DROP
        
        # 2. Stateful inspection (приоритетнее статических правил)
        stateful_result, stateful_reason = self.check_stateful(packet, direction)
        if stateful_result is not None:
            if stateful_result is False:
                print(f"   ❌ Stateful блокировка: {stateful_reason}")
                self.stats['dropped'] += 1
                return Action.DROP
            else:
                print(f"   📊 {stateful_reason}")
                # Stateful разрешил - всё равно проверим прикладной уровень
        else:
            # 3. Статические правила (пакетная фильтрация)
            rule_matched = False
            for rule in self.rules:
                if rule['direction'] and rule['direction'] != direction:
                    continue
                if rule['port'] and rule['port'] != packet.dst_port:
                    continue
                if rule['src_ip'] and rule['src_ip'] != packet.src_ip:
                    continue
                if rule['dst_ip'] and rule['dst_ip'] != packet.dst_ip:
                    continue
                
                # Проверка условий (DMZ, internal)
                if rule.get('condition'):
                    if rule['condition'] == 'dmz_only' and packet.dst_ip not in self.dmz_zone:
                        continue
                    if rule['condition'] == 'internal_only' and packet.src_ip not in self.internal_network:
                        continue
                
                rule_matched = True
                if rule['action'] == Action.ALLOW:
                    print(f"   📋 Правило #{rule['id']} ПРОПУСКАЕТ: {rule['reason']}")
                    break
                else:
                    print(f"   📋 Правило #{rule['id']} БЛОКИРУЕТ: {rule['reason']}")
                    self.stats['dropped'] += 1
                    return rule['action']
            
            if not rule_matched:
                # Пакет не подошёл ни под одно правило -> отбрасываем
                print(f"   ❌ Нет подходящего правила -> отбрасываем")
                self.stats['dropped'] += 1
                return Action.DROP
        
        # 4. Прикладной уровень
        app_ok, app_reason = self.check_application_layer(packet, direction)
        if not app_ok:
            print(f"   🔒 {app_reason}")
            self.stats['dropped'] += 1
            return Action.DROP
        
        # Все проверки пройдены
        self.stats['allowed'] += 1
        print(f"   ✅ ПАКЕТ РАЗРЕШЁН")
        return Action.ALLOW
    
    def print_stats(self):
        """Вывод статистики"""
        print("\n" + "=" * 60)
        print(f"📊 СТАТИСТИКА БРАНДМАУЭРА «{self.name}»")
        print("=" * 60)
        print(f"Всего пакетов:     {self.stats['packets_processed']}")
        print(f"Пропущено:         {self.stats['allowed']} ({self.stats['allowed'] / max(1,self.stats['packets_processed']) * 100:.1f}%)")
        print(f"Отброшено:         {self.stats['dropped']} ({self.stats['dropped'] / max(1,self.stats['packets_processed']) * 100:.1f}%)")
        print(f"Обнаружено спуфинга: {self.stats['spoofing_detected']}")
        print(f"Активных соединений: {len(self.connections)}")
        print("=" * 60)


# ============= ДЕМОНСТРАЦИЯ =============
def demo():
    print("🔒 ЗАПУСК СИМУЛЯТОРА БРАНДМАУЭРА")
    print("=" * 60)
    
    # Создаём брандмауэр
    fw = Firewall("Корпоративный щит")
    
    # Настраиваем сети
    fw.set_internal_network({"192.168.1.10", "192.168.1.20", "192.168.1.100"})
    fw.set_dmz({"10.0.0.5", "10.0.0.6"})  # Веб-серверы в DMZ
    
    # Добавляем дополнительные правила
    fw.add_rule(port = 3389, action = Action.DROP, direction = PacketDirection.INBOUND, reason = "RDP заблокирован извне")
    fw.blacklisted_ips.add("5.5.5.5")
    
    # Тестовые пакеты
    test_packets = [
        # 1. Нормальный веб-запрос из внутренней сети
        Packet("192.168.1.10", "93.184.216.34", 54321, 80, "TCP", "GET /index.html HTTP/1.1\r\nHost: example.com\r\n", flags = {"SYN"}),
        
        # 2. Ответ от веб-сервера (stateful должен пропустить)
        Packet("93.184.216.34", "192.168.1.10", 80, 54321, "TCP", "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n", flags = {"ACK"}),
        
        # 3. Попытка взлома - спуфинг
        Packet("192.168.1.100", "10.0.0.5", 6666, 22, "TCP", flags = {"SYN"}),
        
        # 4. Входящий SYN на внутренний хост (должен быть заблокирован stateful)
        Packet("8.8.8.8", "192.168.1.20", 12345, 22, "TCP", flags = {"SYN"}),
        
        # 5. P2P файлообмен через порт 80 (обход порта, но пойман прикладным уровнем)
        Packet("192.168.1.10", "1.2.3.4", 54322, 80, "TCP", "GET /announce?info_hash=1234567890abcdef HTTP/1.1\r\n", flags = {"SYN"}),
        
        # 6. Попытка утечки секретных данных
        Packet("192.168.1.20", "8.8.8.8", 55555, 25, "TCP", "MAIL FROM:<alice@company.com>\r\nRCPT TO:<spy@external.com>\r\nSubject: Секретный документ\r\n\r\nСодержит пароль: admin123", flags = {"SYN"}),
        
        # 7. Заблокированный порт Finger
        Packet("4.4.4.4", "192.168.1.10", 8888, 79, "TCP", flags = {"SYN"}),
        
        # 8. Запрос к DMZ (разрешён)
        Packet("8.8.8.8", "10.0.0.5", 44444, 80, "TCP", "GET /company-website.html HTTP/1.1\r\nHost: www.company.com\r\n", flags = {"SYN"}),
        
        # 9. Попытка прямого доступа к внутреннему серверу через HTTP (заблокирован)
        Packet("8.8.8.8", "192.168.1.100", 44445, 80, "TCP", "GET /internal-admin.html HTTP/1.1\r\n", flags = {"SYN"}),
    ]
    
    # Обрабатываем пакеты
    for i, packet in enumerate(test_packets, 1):
        print(f"\n{'─' * 50}")
        print(f"Тест #{i}")
        print('─' * 50)
        
        # Определяем направление
        if packet.dst_ip in fw.internal_network or packet.dst_ip in fw.dmz_zone:
            direction = PacketDirection.INBOUND
        else:
            direction = PacketDirection.OUTBOUND
        
        fw.process_packet(packet, direction)
        time.sleep(0.3)  # Небольшая задержка для читаемости
    
    # Итоговая статистика
    fw.print_stats()
    
    # Вывод философского итога из текста
    print("\n💡 «Брандмауэры — это компромисс между безопасностью и функциональностью.")
    print("   Они нарушают стандартную иерархию протоколов, но без них нельзя.")
    print("   Эшелонированная защита (defense in depth) — единственный разумный подход.»")
    print("   — Из классического учебника по компьютерным сетям\n")


if __name__ == "__main__":
    demo()