#!/usr/bin/env python3
"""
    ================================================================================
    КОМПЛЕКТНАЯ ПРОГРАММА: PPP (Point-to-Point Protocol) - полная реализация
    ================================================================================
    На основе RFC 1661, RFC 1662

    Данный файл объединяет четыре учебные программы, иллюстрирующие:
    1. Байт-стаффинг PPP (ядро протокола)
    2. Формат кадра PPP с контрольной суммой CRC-16
    3. Эмуляцию конечного автомата LCP (фазы: DEAD → ESTABLISH → AUTHENTICATE → NETWORK → OPEN → TERMINATE)
    4. Инкапсуляцию IP в PPP (полный стек)

    Автор: Объединённая версия на основе исходных программ
    ================================================================================
"""

import struct
import socket
import time
from enum import Enum
from dataclasses import dataclass
from typing import Optional, Dict, Tuple

# ================================================================================
# КОНСТАНТЫ PPP
# ================================================================================

# Флаги и управляющие байты
FLAG = 0x7E                      # 01111110 - флаговый байт
ESCAPE = 0x7D                    # 01111101 - escape-байт
XOR_MASK = 0x20                  # маска для экранирования

# Поля кадра
ADDRESS_BROADCAST = 0xFF         # широковещательный адрес (все станции)
CONTROL_UNNUMBERED = 0x03        # ненумерованный режим

# Протоколы (наиболее распространённые)
PROTOCOL_IP = 0x0021             # IPv4
PROTOCOL_IPV6 = 0x0057           # IPv6
PROTOCOL_LCP = 0xC021            # Link Control Protocol
PROTOCOL_PAP = 0xC023            # Password Authentication Protocol
PROTOCOL_CHAP = 0xC223           # Challenge-Handshake Authentication Protocol
PROTOCOL_IPCP = 0x8021           # IP Control Protocol

# ================================================================================
# ЧАСТЬ 1: БАЙТ-СТАФФИНГ (CORE MECHANISM)
# ================================================================================

def ppp_stuff(data: bytes) -> bytes:
    """
        Выполняет байт-стаффинг PPP.
        Заменяет:
        0x7E (FLAG) -> 0x7D 0x5E
        0x7D (ESCAPE) -> 0x7D 0x5D
        
        Это необходимо, чтобы флаговый байт не встречался внутри кадра.
    """
    result = bytearray()
    for byte in data:
        if byte == FLAG:
            result.append(ESCAPE)
            result.append(FLAG ^ XOR_MASK)      # 0x5E
        elif byte == ESCAPE:
            result.append(ESCAPE)
            result.append(ESCAPE ^ XOR_MASK)    # 0x5D
        else:
            result.append(byte)
    return bytes(result)


def ppp_unstuff(data: bytes) -> bytes:
    """
        Выполняет обратный байт-стаффинг.
        Восстанавливает исходные данные после приёма.
    """
    result = bytearray()
    i = 0
    while i < len(data):
        byte = data[i]
        if byte == ESCAPE:
            if i + 1 >= len(data):
                raise ValueError("Ошибка: неожиданный конец после ESCAPE-байта")
            next_byte = data[i + 1]
            result.append(next_byte ^ XOR_MASK)
            i += 2
        else:
            result.append(byte)
            i += 1
    return bytes(result)


def add_flags(frame: bytes) -> bytes:
    """Обрамляет кадр флагами 0x7E в начале и конце"""
    return bytes([FLAG]) + frame + bytes([FLAG])


def remove_flags(raw: bytes) -> bytes:
    """Удаляет флаги по краям кадра"""
    if raw and raw[0] == FLAG:
        raw = raw[1:]
    if raw and raw[-1] == FLAG:
        raw = raw[:-1]
    return raw


# ================================================================================
# ЧАСТЬ 2: CRC И ФОРМИРОВАНИЕ КАДРА
# ================================================================================

def crc16_ppp(data: bytes) -> int:
    """
        CRC-16/CCITT-FALSE для PPP.
        Полином: 0x1021 (x^16 + x^12 + x^5 + 1)
        Начальное значение: 0xFFFF
        Без инверсии результата.
    """
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def build_ppp_frame(protocol: int, payload: bytes, compress_address_control: bool = False, compress_protocol: bool = False) -> bytes:
    """
        Собрать полный PPP кадр.
        
        Параметры:
            protocol: номер протокола (например, 0x0021 для IP)
            payload: полезная нагрузка (данные)
            compress_address_control: если True - пропустить поля Address и Control (ACFC)
            compress_protocol: если True - использовать 1-байтовое поле Protocol (PFC)
        
        Формат кадра:
            [Flag(1)] [Address(1)] [Control(1)] [Protocol(1-2)] [Payload(N)] [FCS(2)] [Flag(1)]
    """
    # Поле Protocol (2 байта, big-endian по умолчанию)
    if compress_protocol and (protocol & 0xFF00) == 0:
        # Протокол можно сжать до 1 байта (только если старший байт = 0)
        protocol_field = bytes([protocol & 0xFF])
    else:
        protocol_field = struct.pack('>H', protocol)
    
    # Сборка кадра без FCS
    if compress_address_control:
        # Режим сжатия Address и Control (как упоминается в тексте)
        frame_without_fcs = protocol_field + payload
    else:
        # Полный формат с Address и Control
        frame_without_fcs = bytes([ADDRESS_BROADCAST, CONTROL_UNNUMBERED]) + protocol_field + payload
    
    # Вычисление FCS (Frame Check Sequence)
    fcs = crc16_ppp(frame_without_fcs)
    fcs_bytes = struct.pack('<H', fcs)      # little-endian согласно PPP
    
    # Байт-стаффинг и добавление флагов
    stuffed = ppp_stuff(frame_without_fcs + fcs_bytes)
    return bytes([FLAG]) + stuffed + bytes([FLAG])


def parse_ppp_frame(frame: bytes, compress_address_control: bool = False, compress_protocol: bool = False) -> Dict:
    """
        Разобрать PPP кадр и извлечь поля.
        
        Возвращает словарь с ключами:
            'protocol': номер протокола
            'payload': полезная нагрузка
            'fcs_ok': bool (прошла ли проверка CRC)
            'address': байт Address (если присутствует)
            'control': байт Control (если присутствует)
    """
    result = {'fcs_ok': False}
    
    # 1. Проверка и удаление флагов
    if len(frame) < 4 or frame[0] != FLAG or frame[-1] != FLAG:
        raise ValueError("Некорректные флаги: кадр должен начинаться и заканчиваться на 0x7E")
    inner = frame[1:-1]
    
    # 2. Распаковка байт-стаффинга
    unstuffed = ppp_unstuff(inner)
    
    offset = 0
    
    # 3. Address и Control (опционально)
    if not compress_address_control:
        if unstuffed[0] != ADDRESS_BROADCAST:
            raise ValueError(f"Неверный Address: ожидался 0xFF, получен 0x{unstuffed[0]:02X}")
        if unstuffed[1] != CONTROL_UNNUMBERED:
            raise ValueError(f"Неверный Control: ожидался 0x03, получен 0x{unstuffed[1]:02X}")
        result['address'] = unstuffed[0]
        result['control'] = unstuffed[1]
        offset = 2
    
    # 4. Protocol (1 или 2 байта)
    if compress_protocol and (unstuffed[offset] & 0x01) == 1:
        # 1-байтовый протокол (сжатый)
        protocol = unstuffed[offset]
        offset += 1
    else:
        # 2-байтовый протокол
        protocol = struct.unpack('>H', unstuffed[offset:offset + 2])[0]
        offset += 2
    
    result['protocol'] = protocol
    
    # 5. Payload - всё до последних 2 байт (FCS)
    if len(unstuffed) < offset + 2:
        raise ValueError("Кадр слишком короткий: нет места для FCS")
    
    payload = unstuffed[offset:-2]
    result['payload'] = payload
    
    # 6. Проверка CRC
    received_fcs = struct.unpack('<H', unstuffed[-2:])[0]
    frame_without_fcs = unstuffed[:-2]
    calculated_fcs = crc16_ppp(frame_without_fcs)
    
    result['fcs_ok'] = (calculated_fcs == received_fcs)
    result['calculated_fcs'] = calculated_fcs
    result['received_fcs'] = received_fcs
    
    if not result['fcs_ok']:
        raise ValueError(f"Ошибка CRC: вычислено 0x{calculated_fcs:04X}, получено 0x{received_fcs:04X}")
    
    return result


# ================================================================================
# ЧАСТЬ 3: LCP КОНЕЧНЫЙ АВТОМАТ (ФАЗЫ СОЕДИНЕНИЯ)
# ================================================================================

class Phase(Enum):
    """Фазы соединения PPP согласно RFC 1661"""
    DEAD = "DEAD (отключена) - физическое соединение отсутствует"
    ESTABLISH = "ESTABLISH (установление соединения) - переговоры LCP"
    AUTHENTICATE = "AUTHENTICATE (аутентификация) - проверка подлинности"
    NETWORK = "NETWORK (сеть) - настройка NCP"
    OPEN = "OPEN (открыть) - передача данных"
    TERMINATE = "TERMINATE (завершить) - закрытие соединения"


class LcpEvent(Enum):
    """События, переводящие конечный автомат LCP"""
    PHYSICAL_UP = "Физическое соединение установлено (кабель подключён)"
    LCP_NEGOTIATION_DONE = "LCP переговоры успешны (MRU, аутентификация, сжатие)"
    AUTH_SUCCESS = "Аутентификация пройдена (PAP/CHAP успешны)"
    AUTH_FAILURE = "Аутентификация не пройдена"
    NCP_CONFIG_DONE = "NCP настроен (IP-адреса назначены)"
    DATA_TRANSMISSION_DONE = "Передача данных завершена"
    CLOSE = "Инициативное закрытие соединения"
    DOWN = "Физический канал упал (обрыв линии)"


@dataclass
class LcpStateMachine:
    """
        Конечный автомат для управления фазами LCP.
        Реализует логику, описанную в тексте:
        DEAD → ESTABLISH → AUTHENTICATE → NETWORK → OPEN → TERMINATE → DEAD
    """
    phase: Phase = Phase.DEAD
    peer_authenticated: bool = False
    ip_assigned: bool = False
    lcp_options_negotiated: Dict = None
    
    def __post_init__(self):
        self.lcp_options_negotiated = {
            'mru': 1500,           # Maximum Receive Unit
            'asyncmap': 0,         # Асинхронная карта управления
            'auth_protocol': None, # PAP, CHAP или None
            'magic_number': None,  # Для обнаружения зацикливания
            'acfc': False,         # Сжатие Address/Control
            'pfc': False           # Сжатие Protocol
        }
    
    def handle_event(self, event: LcpEvent) -> str:
        """Обработать событие и вернуть сообщение о переходе"""
        messages = []
        
        if self.phase == Phase.DEAD:
            if event == LcpEvent.PHYSICAL_UP:
                self.phase = Phase.ESTABLISH
                messages.append("🔌 Физическое соединение установлено")
                messages.append("   → Переход в фазу ESTABLISH")
                messages.append("   → Начинаются переговоры LCP (Configure-Request/Configure-Ack)")
        
        elif self.phase == Phase.ESTABLISH:
            if event == LcpEvent.LCP_NEGOTIATION_DONE:
                self.phase = Phase.AUTHENTICATE
                messages.append("🤝 LCP переговоры успешно завершены")
                messages.append("   → Переход в фазу AUTHENTICATE")
                messages.append("   → Запрос аутентификации (PAP/CHAP)")
            elif event == LcpEvent.DOWN:
                self.phase = Phase.DEAD
                messages.append("💀 Физический канал потерян")
                messages.append("   → Переход в фазу DEAD")
        
        elif self.phase == Phase.AUTHENTICATE:
            if event == LcpEvent.AUTH_SUCCESS:
                self.peer_authenticated = True
                self.phase = Phase.NETWORK
                messages.append("✅ Аутентификация успешна")
                messages.append("   → Переход в фазу NETWORK")
                messages.append("   → Запуск NCP (например, IPCP для назначения IP-адресов)")
            elif event == LcpEvent.AUTH_FAILURE:
                self.phase = Phase.TERMINATE
                messages.append("❌ Аутентификация не пройдена")
                messages.append("   → Переход в фазу TERMINATE")
            elif event == LcpEvent.DOWN:
                self.phase = Phase.DEAD
                messages.append("💀 Канал упал во время аутентификации")
                messages.append("   → Переход в фазу DEAD")
        
        elif self.phase == Phase.NETWORK:
            if event == LcpEvent.NCP_CONFIG_DONE:
                self.ip_assigned = True
                self.phase = Phase.OPEN
                messages.append("🌐 NCP настроен (IP-адреса назначены)")
                messages.append("   → Переход в фазу OPEN")
                messages.append("   → Можно передавать IP-пакеты в PPP-кадрах")
            elif event == LcpEvent.DOWN:
                self.phase = Phase.DEAD
                messages.append("💀 Канал упал во время настройки NCP")
                messages.append("   → Переход в фазу DEAD")
        
        elif self.phase == Phase.OPEN:
            if event == LcpEvent.DATA_TRANSMISSION_DONE:
                self.phase = Phase.TERMINATE
                messages.append("📦 Передача данных завершена")
                messages.append("   → Переход в фазу TERMINATE")
                messages.append("   → Отправка LCP Terminate-Request")
            elif event == LcpEvent.CLOSE:
                self.phase = Phase.TERMINATE
                messages.append("🔚 Инициативное закрытие соединения")
                messages.append("   → Переход в фазу TERMINATE")
            elif event == LcpEvent.DOWN:
                self.phase = Phase.DEAD
                messages.append("💀 Внезапный обрыв канала во время передачи")
                messages.append("   → Переход в фазу DEAD")
        
        elif self.phase == Phase.TERMINATE:
            if event == LcpEvent.DOWN:
                self.phase = Phase.DEAD
                messages.append("💀 Физическое соединение разорвано")
                messages.append("   → Переход в фазу DEAD")
        
        if not messages:
            messages.append(f"⏭️ Событие '{event.value}' игнорируется в фазе {self.phase.value}")
        
        return "\n".join(messages)
    
    def get_phase(self) -> str:
        """Вернуть текущую фазу в читаемом виде"""
        return f"📌 Текущая фаза: {self.phase.value}"
    
    def get_options(self) -> str:
        """Вернуть согласованные LCP опции"""
        return f"   LCP опции: MRU={self.lcp_options_negotiated['mru']}, " \
               f"ACFC={self.lcp_options_negotiated['acfc']}, " \
               f"PFC={self.lcp_options_negotiated['pfc']}"


# ================================================================================
# ЧАСТЬ 4: ИНКАПСУЛЯЦИЯ IP В PPP (ПОЛНЫЙ СТЕК)
# ================================================================================

def create_dummy_ip_packet(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    """
        Создание простого UDP-пакета внутри IP (учебный, для демонстрации).
        
        Формат: IP header (20 байт) + UDP header (8 байт) + данные
    """
    # IP header (минимальный, 20 байт)
    version_ihl = 0x45           # IPv4, IHL=5 (20 байт)
    tos = 0
    total_len = 20 + 8 + len(payload)
    packet_id = 12345
    flags_frag = 0
    ttl = 64
    protocol = 17                # UDP
    
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    
    # IP header без контрольной суммы
    ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, tos, total_len, packet_id, flags_frag, ttl, protocol, 0, src, dst)
    
    # UDP header + данные
    udp_src_port = 1234
    udp_dst_port = 53           # DNS порт как пример
    udp_len = 8 + len(payload)
    udp_header = struct.pack('!HHHH', udp_src_port, udp_dst_port, udp_len, 0)
    udp_packet = udp_header + payload
    
    # Собираем IP пакет
    ip_packet = ip_header + udp_packet
    
    # Вычисление IP контрольной суммы
    ip_checksum = 0
    for i in range(0, len(ip_header), 2):
        if i == 10:              # пропустить поле checksum
            continue
        word = (ip_header[i] << 8) + ip_header[i+1]
        ip_checksum += word
        while ip_checksum > 0xFFFF:
            ip_checksum = (ip_checksum & 0xFFFF) + (ip_checksum >> 16)
    ip_checksum = ~ip_checksum & 0xFFFF
    
    # Вставить вычисленную контрольную сумму
    ip_packet = ip_packet[:10] + struct.pack('!H', ip_checksum) + ip_packet[12:]
    
    return ip_packet


def create_ppp_from_ip(ip_packet: bytes, compress_ac: bool = False) -> bytes:
    """Упаковка IP-пакета в PPP кадр"""
    return build_ppp_frame(PROTOCOL_IP, ip_packet, compress_address_control=compress_ac)


def extract_ip_from_ppp(ppp_frame: bytes, compress_ac: bool = False) -> bytes:
    """Извлечение IP-пакета из PPP кадра с проверкой"""
    parsed = parse_ppp_frame(ppp_frame, compress_address_control=compress_ac)
    
    if parsed['protocol'] != PROTOCOL_IP:
        raise ValueError(f"Не IP протокол в кадре: 0x{parsed['protocol']:04X}")
    
    return parsed['payload']


# ================================================================================
# ДЕМОНСТРАЦИОННЫЕ ФУНКЦИИ
# ================================================================================

def demo_byte_stuffing():
    """Демонстрация №1: байт-стаффинг"""
    print("\n" + "="*80)
    print("ДЕМОНСТРАЦИЯ 1: БАЙТ-СТАФФИНГ PPP")
    print("="*80)
    print("(Из текста: 'В РРР применяется байт-стаффинг, поэтому все фреймы состоят из целого числа байтов')\n")
    
    test_data = b"\x7EHello\x7DWorld\x7E"
    print(f"Исходные данные:     {test_data}")
    print(f"  (содержит FLAG=0x7E и ESCAPE=0x7D)")
    
    stuffed = ppp_stuff(test_data)
    print(f"\nПосле стаффинга:     {stuffed}")
    print(f"  (FLAG заменён на 0x7D 0x5E, ESCAPE на 0x7D 0x5D)")
    
    unstuffed = ppp_unstuff(stuffed)
    print(f"\nПосле анстаффинга:   {unstuffed}")
    
    full_frame = add_flags(stuffed)
    print(f"\nПолный кадр с флагами: {full_frame}")
    
    received = remove_flags(full_frame)
    decoded = ppp_unstuff(received)
    
    print(f"\nИтог: {'✓' if decoded == test_data else '✗'} Данные восстановлены корректно")


def demo_frame_format():
    """Демонстрация №2: формат кадра и CRC"""
    print("\n" + "=" * 80)
    print("ДЕМОНСТРАЦИЯ 2: ФОРМАТ КАДРА PPP И CRC")
    print("=" * 80)
    print("(Из текста: 'Формат фреймов также обеспечивает обнаружение ошибок')\n")
    
    # Тестовые данные
    test_payload = b"Test payload for PPP frame"
    
    print(f"Полезная нагрузка: '{test_payload.decode()}'")
    
    # Кадр в полном формате
    frame_full = build_ppp_frame(PROTOCOL_IP, test_payload, compress_address_control=False)
    print(f"\nПолный кадр (с Address/Control): {len(frame_full)} байт")
    print(f"  {frame_full.hex(' ')}")
    
    # Кадр со сжатием Address/Control (как упоминается в тексте)
    frame_compressed = build_ppp_frame(PROTOCOL_IP, test_payload, compress_address_control=True)
    print(f"\nСжатый кадр (без Address/Control): {len(frame_compressed)} байт")
    print(f"  {frame_compressed.hex(' ')}")
    
    # Разбор кадра
    parsed = parse_ppp_frame(frame_full, compress_address_control=False)
    print(f"\nРазбор кадра:")
    print(f"  Protocol: 0x{parsed['protocol']:04X} {'(IP)' if parsed['protocol'] == PROTOCOL_IP else ''}")
    print(f"  Payload: '{parsed['payload'].decode()}'")
    print(f"  FCS: {'✓ OK' if parsed['fcs_ok'] else '✗ Ошибка'}")
    
    # Демонстрация обнаружения ошибки
    print("\n--- Проверка обнаружения ошибки ---")
    corrupted_frame = bytearray(frame_full)
    corrupted_frame[20] ^= 0xFF  # инвертируем байт
    try:
        parse_ppp_frame(bytes(corrupted_frame), compress_address_control=False)
    except ValueError as e:
        print(f"  ✗ Ошибка обнаружена: {e}")


def demo_lcp_state_machine():
    """Демонстрация №3: конечный автомат LCP"""
    print("\n" + "=" * 80)
    print("ДЕМОНСТРАЦИЯ 3: LCP - ФАЗЫ СОЕДИНЕНИЯ")
    print("=" * 80)
    print("(Из текста: 'линия переходит в состояние ESTABLISH... AUTHENTICATE... NETWORK... OPEN')\n")
    
    lsm = LcpStateMachine()
    
    # Сценарий из текста
    scenario = [
        ("Физическое соединение создано", LcpEvent.PHYSICAL_UP),
        ("LCP переговоры (MRU=1500, ACFC, PFC, магическое число)", LcpEvent.LCP_NEGOTIATION_DONE),
        ("Успешная аутентификация (PAP или CHAP)", LcpEvent.AUTH_SUCCESS),
        ("NCP конфигурация (IPCP - назначение IP-адресов)", LcpEvent.NCP_CONFIG_DONE),
        ("Передача IP-пакетов в PPP-кадрах", LcpEvent.DATA_TRANSMISSION_DONE),
        ("Завершение соединения", LcpEvent.CLOSE),
        ("Разрыв физического канала", LcpEvent.DOWN),
    ]
    
    print("Последовательность фаз (согласно RFC 1661):\n")
    
    for description, event in scenario:
        print(f"📌 {description}:")
        print(f"   Событие: {event.value}")
        result = lsm.handle_event(event)
        print(f"   {result}")
        print(f"   {lsm.get_phase()}")
        print(lsm.get_options())
        print()
        time.sleep(0.3)  # пауза для читаемости


def demo_ip_over_ppp():
    """Демонстрация №4: полная инкапсуляция IP в PPP"""
    print("\n" + "=" * 80)
    print("ДЕМОНСТРАЦИЯ 4: ИНКАПСУЛЯЦИЯ IP В PPP")
    print("=" * 80)
    print("(Из текста: 'в этой фазе IР-пакеты пересылаются в РРР-фреймах по линии')\n")
    
    # 1. Создаём IP-пакет
    message = b"Hello, PPP over SONET/ADSL/DOCSIS!"
    ip_packet = create_dummy_ip_packet("192.168.1.100", "8.8.8.8", message)
    
    print(f"1. Создан IP-пакет: {len(ip_packet)} байт")
    print(f"   IP header (первые 20 байт): {ip_packet[:20].hex(' ')}")
    print(f"   Данные: '{ip_packet[28:].decode()}'")
    
    # 2. Упаковываем в PPP
    ppp_frame = create_ppp_from_ip(ip_packet, compress_ac=False)
    print(f"\n2. PPP кадр: {len(ppp_frame)} байт")
    print(f"   Первые 10 байт: {ppp_frame[:10].hex(' ')}")
    print(f"   Последние 10 байт: {ppp_frame[-10:].hex(' ')}")
    
    # 3. Симуляция передачи по каналу
    print(f"\n3. Передача по физическому каналу (SONET/ADSL/DOCSIS)...")
    received_frame = ppp_frame  # канал без ошибок
    
    # 4. Извлечение IP
    extracted_ip = extract_ip_from_ppp(received_frame, compress_ac=False)
    print(f"\n4. Извлечённый IP-пакет: {len(extracted_ip)} байт")
    
    # 5. Проверка
    if extracted_ip == ip_packet:
        print(f"   ✅ IP-пакет восстановлен корректно!")
        print(f"   Данные: '{extracted_ip[28:].decode()}'")
    else:
        print(f"   ❌ Ошибка: пакеты не совпадают")
    
    # 6. Дополнительно: демонстрация сжатого режима
    print(f"\n--- Дополнительно: сжатый режим (без Address/Control) ---")
    ppp_compressed = create_ppp_from_ip(ip_packet, compress_ac=True)
    print(f"   Размер кадра без сжатия: {len(ppp_frame)} байт")
    print(f"   Размер кадра со сжатием: {len(ppp_compressed)} байт")
    print(f"   Экономия: {len(ppp_frame) - len(ppp_compressed)} байт на кадр")
    
    extracted_compressed = extract_ip_from_ppp(ppp_compressed, compress_ac=True)
    if extracted_compressed == ip_packet:
        print(f"   ✅ Сжатый режим работает корректно")


def demo_pppoe_analogy():
    """Дополнительная демонстрация: сравнение с PPPoE (из контекста ADSL)"""
    print("\n" + "=" * 80)
    print("ДОПОЛНИТЕЛЬНО: PPPoE (PPP over Ethernet) для ADSL")
    print("=" * 80)
    print("(Из текста: 'вторым примером является использование каналов ADSL')\n")
    
    print("В ADSL PPP часто используется поверх Ethernet (PPPoE):")
    print("  [Ethernet header] [PPPoE header] [PPP frame]")
    print("\nПример инкапсуляции PPP в Ethernet для ADSL:")
    
    # Имитация Ethernet кадра с PPPoE
    ethernet_header = bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  # MAC назначения
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,  # MAC источника
        0x88, 0x63                           # EtherType: PPPoE Discovery
    ])
    
    pppoe_header = bytes([
        0x11,        # Version=1, Type=1
        0x00,        # Code (Discovery)
        0x00, 0x01,  # Session ID
        0x00, 0x08   # Length
    ])
    
    # Создаём PPP кадр
    test_ip = create_dummy_ip_packet("10.0.0.1", "10.0.0.2", b"ADSL test data")
    ppp_frame = create_ppp_from_ip(test_ip)
    
    # Собираем полный Ethernet кадр
    eth_pppoe_frame = ethernet_header + pppoe_header + ppp_frame
    
    print(f"  Полный Ethernet+PPPoE+PPP кадр: {len(eth_pppoe_frame)} байт")
    print(f"  Ethernet header: 14 байт")
    print(f"  PPPoE header: 6 байт")
    print(f"  PPP frame: {len(ppp_frame)} байт")
    print("\n  Это позволяет передавать PPP через Ethernet-сети (стандарт RFC 2516)")


# ================================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ================================================================================

def main():
    """Запуск всех демонстраций"""
    print("\n" + "=" * 80)
    print("PPP (POINT-TO-POINT PROTOCOL) - ПОЛНАЯ РЕАЛИЗАЦИЯ")
    print("=" * 80)
    print("Основано на RFC 1661, RFC 1662, RFC 2615")
    print("Иллюстрирует механизмы, описанные в тексте про SONET, ADSL, DOCSIS")
    
    # Запуск всех демонстраций
    demo_byte_stuffing()
    demo_frame_format()
    demo_lcp_state_machine()
    demo_ip_over_ppp()
    demo_pppoe_analogy()
    
    # Итог
    print("\n" + "=" * 80)
    print("ИТОГ")
    print("=" * 80)
    print("""
        Данная программа демонстрирует все ключевые механизмы PPP:
        
        1. ✓ Байт-стаффинг (отличие от бит-ориентированного HDLC)
        2. ✓ Формат кадра: Flag(0x7E) + Address(0xFF) + Control(0x03) + Protocol + Payload + FCS
        3. ✓ CRC-16 для обнаружения ошибок
        4. ✓ Фазы LCP: DEAD → ESTABLISH → AUTHENTICATE → NETWORK → OPEN → TERMINATE
        5. ✓ Инкапсуляция IP-пакетов в PPP
        6. ✓ Сжатие полей Address/Control (как упоминается в тексте)
        
        Эти механизмы используются в:
            - SONET (оптоволоконные каналы провайдеров)
            - ADSL (телефонная 'последняя миля')
            - DOCSIS (кабельные сети)
    """)
    
    print("\n✅ Все демонстрации завершены успешно!")


if __name__ == "__main__":
    main()