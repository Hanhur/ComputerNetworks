"""
Учебная модель VPN на основе текста:
- Инкапсуляция (туннелирование) IP-пакета в другой IP-пакет
- Создание Security Association (SA) между двумя "офисами"
- Отличие частной сети от VPN поверх интернета
"""
import hashlib
import json
import random
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

# ------------------- Модели данных -------------------

@dataclass
class InnerPacket:
    """Оригинальный пакет внутри частной сети (не видный интернету)"""
    src_ip: str      # IP внутри компании (например, 10.0.1.5)
    dst_ip: str      # IP внутри компании (10.0.2.8)
    payload: str     # Данные (например, "секретный отчет")
    protocol: str = "TCP"

@dataclass
class OuterPacket:
    """Пакет, идущий по интернету (виден маршрутизаторам)"""
    src_ip: str      # Внешний IP брандмауэра офиса А
    dst_ip: str      # Внешний IP брандмауэра офиса Б
    encrypted_data: bytes  # Зашифрованное + инкапсулированное содержимое
    esp_header: Dict[str, str]  # IPsec ESP в режиме туннелирования

class SecurityAssociation:
    """Модель SA - договоренность между двумя брандмауэрами"""
    def __init__(self, office_a_id: str, office_b_id: str):
        self.office_a = office_a_id
        self.office_b = office_b_id
        self.key = hashlib.sha256(f"{office_a_id}:{office_b_id}:{random.randint(1, 10000)}".encode()).digest()
        self.spi = random.randint(1000, 9999)  # Security Parameters Index
        self.encryption_algo = "AES-256 (симулирован)"
        self.mode = "Туннельный (Tunnel mode)"
        print(f"[SA] Создан Security Association между {office_a_id} и {office_b_id}")
        print(f"    Параметры: SPI = {self.spi}, Алгоритм = {self.encryption_algo}, Режим = {self.mode}")

    def encrypt_and_encapsulate(self, inner: InnerPacket) -> bytes:
        """Симулирует шифрование + инкапсуляцию (оригинальный пакет вкладывается внутрь)"""
        # Превращаем внутренний пакет в JSON и имитируем шифрование с помощью простого XOR
        inner_data = json.dumps({"src": inner.src_ip, "dst": inner.dst_ip, "payload": inner.payload}).encode()
        # Примитивное "шифрование" (для демонстрации, в реальности AES)
        encrypted = bytes([b ^ 0xAA for b in inner_data])
        # Добавляем заголовок ESP (имитация)
        esp_overhead = f"SPI = {self.spi}|SEQ = {random.randint(1, 9999)}".encode()
        return esp_overhead + encrypted

    def decrypt_and_deencapsulate(self, encrypted_data: bytes) -> InnerPacket:
        """Обратный процесс: расшифровка и извлечение исходного пакета"""
        # Пропускаем ESP-заголовок (первые ~20 байт для демо)
        real_encrypted = encrypted_data[20:] if len(encrypted_data) > 20 else encrypted_data
        # "Расшифровка"
        decrypted = bytes([b ^ 0xAA for b in real_encrypted])
        data = json.loads(decrypted.decode())
        return InnerPacket(src_ip = data["src"], dst_ip = data["dst"], payload = data["payload"])


class FirewallVPNGateway:
    """Модель брандмауэра с поддержкой VPN (как из текста: брандмауэр + IPsec)"""
    def __init__(self, office_name: str, public_ip: str, private_network: str):
        self.office_name = office_name
        self.public_ip = public_ip
        self.private_network = private_network
        self.sa_table: Dict[Tuple[str, str], SecurityAssociation] = {}  # (офис_А, офис_Б) -> SA
        self.routing_table = {}  # Для простоты: "10.0.x.x" -> другой офис

    def establish_sa(self, other_gateway: 'FirewallVPNGateway'):
        """Договор о параметрах SA между двумя брандмауэрами (как в тексте)"""
        sa_key = (self.office_name, other_gateway.office_name)
        if sa_key not in self.sa_table:
            sa = SecurityAssociation(self.office_name, other_gateway.office_name)
            self.sa_table[sa_key] = sa
            # Сохраняем зеркальную запись для другого шлюза (симметрично)
            mirror_key = (other_gateway.office_name, self.office_name)
            other_gateway.sa_table[mirror_key] = sa

    def send_packet_to_internet(self, inner_packet: InnerPacket, dest_firewall: 'FirewallVPNGateway'):
        """Брандмауэр отправляет пакет через интернет-туннель"""
        print(f"\n[{self.office_name}] Брандмауэр получает внутренний пакет: {inner_packet}")
        # Поиск SA для нужного офиса
        sa_key = (self.office_name, dest_firewall.office_name)
        if sa_key not in self.sa_table:
            print(f"  ❌ Нет SA с {dest_firewall.office_name}. Устанавливаю...")
            self.establish_sa(dest_firewall)

        sa = self.sa_table[sa_key]
        # Инкапсуляция + шифрование (IPsec ESP Tunnel Mode)
        encrypted_tunnel_data = sa.encrypt_and_encapsulate(inner_packet)

        # Создаём внешний пакет (видимый в интернете)
        outer = OuterPacket(
            src_ip = self.public_ip,
            dst_ip = dest_firewall.public_ip,
            encrypted_data = encrypted_tunnel_data,
            esp_header = {"SPI": str(sa.spi), "Mode": "Tunnel"}
        )
        print(f"  🔒 Туннелирование: Внутренний {inner_packet.src_ip} -> {inner_packet.dst_ip} упакован в пакет для интернета:")
        print(f"     Внешний IP: {outer.src_ip} -> {outer.dst_ip}")
        print(f"     ESP заголовок: {outer.esp_header}")
        return outer

    def receive_packet_from_internet(self, outer_packet: OuterPacket, src_firewall: 'FirewallVPNGateway'):
        """Приём пакета из интернета, расшифровка, извлечение внутреннего пакета"""
        print(f"\n[{self.office_name}] Брандмауэр получил внешний пакет из интернета от {src_firewall.public_ip}")
        # Ищем соответствующий SA
        sa_key = (src_firewall.office_name, self.office_name)
        if sa_key not in self.sa_table:
            print(f"  ⚠️ Ошибка: нет SA для {src_firewall.office_name}. Пакет отброшен.")
            return None

        sa = self.sa_table[sa_key]
        # Дешифрация и декапсуляция
        inner_packet = sa.decrypt_and_deencapsulate(outer_packet.encrypted_data)
        print(f"  🔓 Расшифровано и извлечено: {inner_packet}")
        print(f"  ✅ Доставлено в частную сеть {self.private_network} получателю {inner_packet.dst_ip}")
        return inner_packet


class InternetRouter:
    """Маршрутизатор интернета (не видит внутренние пакеты VPN)"""
    @staticmethod
    def forward(outer_packet: OuterPacket):
        print(f"\n[Интернет-маршрутизатор] Пересылаю пакет:")
        print(f"    Заголовок IP: {outer_packet.src_ip} -> {outer_packet.dst_ip}")
        print(f"    Обнаружен ESP-заголовок: {outer_packet.esp_header}")
        print(f"    📝 Мне безразлично, что внутри (IPsec), просто пересылаю дальше.")
        return outer_packet  # Просто пересылка


# ------------------- Демонстрация работы -------------------

def main():
    print("=" * 70)
    print("ДЕМОНСТРАЦИЯ VPN НА ОСНОВЕ ТЕКСТА:")
    print("Частная сеть -> Туннель IPsec через интернет -> Частная сеть")
    print("=" * 70)

    # 1. Создаём два офиса с брандмауэрами
    moscow = FirewallVPNGateway("Офис_Москва", "188.43.2.10", "10.0.1.0/24")
    spb = FirewallVPNGateway("Офис_СПб", "95.167.30.5", "10.0.2.0/24")
    internet_router = InternetRouter()

    # 2. Пользователь в Москве отправляет пакет в СПб (внутренний IP)
    original_packet = InnerPacket(
        src_ip = "10.0.1.15",
        dst_ip = "10.0.2.8",
        payload = "Отчет: финансовые результаты Q3 (секретно)"
    )

    print("\n" + "=" * 50)
    print("ШАГ 1: Пакет попадает на брандмауэр Москвы")
    print("=" * 50)

    # 3. Брандмауэр Москвы создаёт туннель и отправляет через интернет
    tunnel_packet = moscow.send_packet_to_internet(original_packet, spb)

    print("\n" + "=" * 50)
    print("ШАГ 2: Пакет идёт через интернет (виден маршрутизаторам)")
    print("=" * 50)

    # 4. Интернет-маршрутизатор пересылает (не обращая внимания на IPsec)
    forwarded = internet_router.forward(tunnel_packet)

    print("\n" + "=" * 50)
    print("ШАГ 3: Брандмауэр СПб получает и расшифровывает")
    print("=" * 50)

    # 5. Брандмауэр СПб принимает и восстанавливает исходный пакет
    received = spb.receive_packet_from_internet(forwarded, moscow)

    print("\n" + "=" * 50)
    print("ИТОГ:")
    print("=" * 50)
    print(f"✅ Оригинальный пакет: {original_packet}")
    print(f"✅ Получен в СПб: {received}")
    print(f"✅ Для приложений в СПб это выглядит как прямая частная линия.")
    print(f"✅ Маршрутизаторы интернета видели только внешние IP {moscow.public_ip}->{spb.public_ip} и ESP заголовок.")
    print("=" * 70)

if __name__ == "__main__":
    main()