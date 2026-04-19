import random
import time
from typing import List, Dict, Tuple

# ------------------- МОДЕЛЬ СЕТИ -------------------
class Packet:
    """Сетевой пакет с IP-адресом источника и назначения"""
    def __init__(self, src_ip: str, dst_ip: str, is_malicious: bool = False, payload: str = ""):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.is_malicious = is_malicious
        self.payload = payload

    def __repr__(self):
        return f"Packet({self.src_ip} -> {self.dst_ip}, malicious={self.is_malicious})"


# ------------------- 1. ФИЛЬТРАЦИЯ -------------------
class Firewall:
    """Брандмауэр с egress и ingress фильтрацией"""
    def __init__(self, internal_networks: List[str]):
        self.internal_networks = internal_networks  # например ['192.168.0.0/16']

    def _ip_in_network(self, ip: str, network: str) -> bool:
        # Упрощённая проверка (только для примера)
        return ip.startswith(network.split('/')[0].rsplit('.', 1)[0])

    def egress_filter(self, packet: Packet) -> bool:
        """
        Выходная фильтрация:
        блокируем исходящие пакеты, у которых IP отправителя НЕ входит в нашу сеть
        """
        allowed = any(self._ip_in_network(packet.src_ip, net) for net in self.internal_networks)
        if not allowed:
            print(f"  [EGRESS] Заблокирован поддельный исходящий пакет: {packet.src_ip} -> {packet.dst_ip}")
        return allowed

    def ingress_filter(self, packet: Packet) -> bool:
        """
        Входная фильтрация:
        блокируем входящие пакеты с внутренними IP-адресами источника
        """
        blocked = any(self._ip_in_network(packet.src_ip, net) for net in self.internal_networks)
        if blocked:
            print(f"  [INGRESS] Заблокирован входящий пакет с внутренним IP источника: {packet.src_ip}")
        return not blocked

    def process_packet(self, packet: Packet, direction: str) -> bool:
        if direction == "egress":
            return self.egress_filter(packet)
        elif direction == "ingress":
            return self.ingress_filter(packet)
        return True


# ------------------- 2. ОБЛАЧНАЯ ЗАЩИТА (SCRUBBER + ABSORPTION) -------------------
class CloudScrubber:
    """Облачный скруббер — поглощает трафик и чистит его"""
    def __init__(self, capacity: int = 1000):
        self.capacity = capacity  # условная пропускная способность
        self.extra_resources = 0

    def absorb_traffic(self, packets: List[Packet]) -> Tuple[List[Packet], int]:
        """
        Пытается "поглотить" DDoS-атаку за счёт резервной мощности
        Возвращает (очищенные пакеты, количество отброшенных)
        """
        total_load = len(packets)
        available = self.capacity + self.extra_resources

        if total_load > available:
            print(f"  [ОБЛАКО] Перегрузка! Трафик {total_load} > {available}. Включаем доп. ресурсы.")
            self.extra_resources += (total_load - available)  # "облако выделяет доп. мощность"
            available = self.capacity + self.extra_resources

        # Скруббинг: удаляем дубликаты и явно вредоносные пакеты
        cleaned = []
        seen = set()
        dropped = 0

        for p in packets:
            # Простая защита от дубликатов (по src+dst)
            key = (p.src_ip, p.dst_ip, p.payload[:20])
            if key in seen:
                dropped += 1
                continue
            seen.add(key)

            if p.is_malicious:
                # Очистка вредоносного трафика (WAF-функция)
                dropped += 1
                continue

            cleaned.append(p)

        print(f"  [ОБЛАКО] Поглощено {total_load} пакетов. Очищено {dropped}. Пропущено {len(cleaned)}.")
        return cleaned, dropped

    def act_as_waf(self, packet: Packet) -> bool:
        """Эмуляция Web Application Firewall"""
        bad_flags = ["SYN+FIN", "XSS", "SQL_INJECT"]
        return not any(bad in packet.payload for bad in bad_flags)


# ------------------- 3. DNS ПЕРЕНАПРАВЛЕНИЕ И СКРЫТИЕ РЕАЛЬНОГО IP -------------------
class DNSRerouter:
    """Скрывает реальный IP сервера через DNS"""
    def __init__(self, real_server_ip: str, cloud_proxy_ip: str):
        self.real_ip = real_server_ip
        self.cloud_proxy_ip = cloud_proxy_ip
        self.leaked = False  # утечка реального IP

    def resolve(self, domain: str, attacker_knows_real_ip: bool = False) -> str:
        if attacker_knows_real_ip or self.leaked:
            print(f"  [DNS] ВНИМАНИЕ! Реальный IP {self.real_ip} скомпрометирован!")
            return self.real_ip
        print(f"  [DNS] Возвращаем облачный IP {self.cloud_proxy_ip} (реальный скрыт)")
        return self.cloud_proxy_ip

    def leak_real_ip(self, via: str):
        """Симуляция утечки через FTP, DNS-архивы или внутриполосную передачу"""
        self.leaked = True
        print(f"  [УТЕЧКА] Реальный IP {self.real_ip} раскрыт через {via}")


# ------------------- 4. BGP BLACKHOLING (упрощённо) -------------------
class BGPRouter:
    """Маршрутизатор с BGP blackholing"""
    def __init__(self, owned_block: str):
        self.owned_block = owned_block  # например "203.0.113.0/24"
        self.blackhole_active = False
        self.cloud_announces = False

    def activate_blackhole(self, cloud_provider_ip: str):
        """Удаляем свои BGP-объявления и передаём их облаку"""
        self.blackhole_active = True
        self.cloud_announces = True
        print(f"  [BGP] Владелец блока {self.owned_block} удалил объявления. Облако {cloud_provider_ip} теперь принимает трафик.")

    def route_packet(self, dst_ip: str) -> str:
        if self.blackhole_active and dst_ip.startswith(self.owned_block.split('/')[0].rsplit('.', 1)[0]):
            print(f"  [BGP] Пакет к {dst_ip} уходит в облако (чёрная дыра отключена)")
            return "CLOUD"
        return "DIRECT"


# ------------------- ДЕМОНСТРАЦИЯ -------------------
def run_ddos_defense_simulation():
    print("=" * 60)
    print("ЗАЩИТА ОТ DDoS-АТАК — СИМУЛЯЦИЯ НА ОСНОВЕ ТЕКСТА")
    print("=" * 60)

    # Данные для симуляции
    internal_net = ["192.168.1.0/24"]
    real_server = "10.0.0.1"
    cloud_proxy = "203.0.113.100"
    domain = "example.com"

    # Создаём компоненты
    fw = Firewall(internal_net)
    cloud = CloudScrubber(capacity = 50)
    dns = DNSRerouter(real_server, cloud_proxy)
    bgp = BGPRouter(owned_block = "203.0.113.0/24")

    # Генерируем трафик (нормальный + DDoS)
    normal_packets = [
        Packet("192.168.1.10", cloud_proxy, is_malicious = False, payload = "GET /index.html"),
        Packet("192.168.1.20", cloud_proxy, is_malicious = False, payload = "POST /login"),
    ]
    attack_packets = [
        Packet("1.2.3.4", cloud_proxy, is_malicious = True, payload = "SYN+FIN"),
        Packet("5.6.7.8", cloud_proxy, is_malicious = True, payload = "XSS"),
        Packet("9.9.9.9", cloud_proxy, is_malicious = False, payload = "GET /"),
        Packet("9.9.9.9", cloud_proxy, is_malicious = False, payload = "GET /"),  # дубликат
    ] * 30  # много пакетов для имитации атаки

    all_traffic = normal_packets + attack_packets
    random.shuffle(all_traffic)

    print("\n1. Фильтрация (egress/ingress)")
    for p in all_traffic[:8]:
        if p.src_ip.startswith("192.168"):
            fw.process_packet(p, "egress")
        else:
            fw.process_packet(p, "ingress")

    print("\n2. Облачное поглощение и скруббинг")
    cleaned, dropped = cloud.absorb_traffic(all_traffic)

    print("\n3. DNS-перенаправление (скрываем реальный IP)")
    for _ in range(3):
        ip = dns.resolve(domain, attacker_knows_real_ip = False)
        print(f"   Посетитель получил IP {ip}")

    print("\n4. Утечка реального IP (как в тексте — FTP, DNS-архивы)")
    dns.leak_real_ip("внутриполосная передача (аналог FTP)")

    print("\n5. Атака в обход облака после утечки")
    ip = dns.resolve(domain, attacker_knows_real_ip = True)
    print(f"   Злоумышленник шлет трафик прямо на {ip} (минуя облако)")

    print("\n6. BGP blackholing (для владельцев блока /24)")
    bgp.activate_blackhole(cloud_proxy)
    test_ips = ["203.0.113.55", "8.8.8.8"]
    for ip in test_ips:
        route = bgp.route_packet(ip)
        print(f"   Пакет к {ip} -> {route}")

    print("\n" + "=" * 60)
    print("ИТОГ: наглядно показаны методы из текста — фильтрация, облако,")
    print("DNS-перенаправление, утечки реального IP, BGP blackholing.")
    print("=" * 60)


if __name__ == "__main__":
    run_ddos_defense_simulation()