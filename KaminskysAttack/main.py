#!/usr/bin/env python3
"""
Демонстрация атаки Каминского (Kaminsky DNS cache poisoning attack)
Сугубо в образовательных целях. Работает только в симуляции.
"""

import random
import string
import asyncio
from dataclasses import dataclass, field
from typing import Dict, Optional, List
from enum import Enum

# ========== Типы DNS-записей (упрощённо) ==========
class QType(Enum):
    A = 1
    NS = 2

@dataclass
class DNSRecord:
    name: str
    qtype: QType
    ttl: int
    rdata: str  # IP или имя сервера

@dataclass
class DNSMessage:
    tx_id: int
    source_port: int
    query_name: str
    query_type: QType
    answers: List[DNSRecord] = field(default_factory = list)
    authorities: List[DNSRecord] = field(default_factory = list)
    additional: List[DNSRecord] = field(default_factory = list)
    is_authoritative: bool = False
    is_recursive_desired: bool = False

# ========== Симулированные DNS-серверы ==========
class AuthoritativeServer:
    """Авторитетный сервер (например, для .nl или vu.nl)"""
    def __init__(self, zone: str, ip: str, nameservers: Dict[str, str]):
        self.zone = zone  # домен, за который отвечает
        self.ip = ip
        self.ns_records = nameservers  # имя -> IP (glue)

    def handle_query(self, msg: DNSMessage) -> Optional[DNSMessage]:
        """Обработка запроса (нерекурсивная)"""
        if not msg.query_name.endswith(self.zone):
            return None  # не моя зона

        response = DNSMessage(
            tx_id = msg.tx_id,
            source_port = msg.source_port,
            query_name = msg.query_name,
            query_type = msg.query_type,
            is_authoritative = True,
            is_recursive_desired = False
        )

        # Для любого поддомена: отдаём NS-записи зоны
        for ns_name, ns_ip in self.ns_records.items():
            response.authorities.append(DNSRecord(name = self.zone, qtype = QType.NS, ttl = 3600, rdata = ns_name))
            # Glue-запись (важный элемент для атаки!)
            response.additional.append(DNSRecord(name = ns_name, qtype = QType.A, ttl = 3600, rdata = ns_ip))
        return response

class LocalResolver:
    """Локальный DNS-резолвер с кэшем"""
    def __init__(self, root_server):
        self.cache: Dict[str, DNSRecord] = {}
        self.root_server = root_server
        self.pending_requests: Dict[tuple, asyncio.Future] = {}  # (name, qtype, port) -> Future

    async def resolve(self, domain: str, qtype: QType, client_port: int) -> Optional[str]:
        """Рекурсивный поиск"""
        # Проверка кэша
        cache_key = f"{domain}:{qtype.value}"
        if cache_key in self.cache:
            record = self.cache[cache_key]
            print(f"  [RESOLVER] Кэш: {domain} -> {record.rdata}")
            return record.rdata

        print(f"  [RESOLVER] Запрос {domain} (ID={client_port % 65535}, порт={client_port})")

        # Симуляция: определяем, кто авторитетный
        # Для простоты: .nl -> root, потом делегация
        current_server = self.root_server
        visited = set()

        while True:
            if current_server.zone in visited:
                print(f"  [RESOLVER] Ошибка: цикл в делегации")
                return None
            visited.add(current_server.zone)

            print(f"  [RESOLVER] Обращаюсь к {current_server.zone} ({current_server.ip})")

            # Формируем запрос
            req = DNSMessage(
                tx_id = random.randint(0, 65535),
                source_port = client_port,
                query_name = domain,
                query_type = qtype
            )

            # Получаем ответ
            response = await self._send_query(current_server, req)
            if response is None:
                return None

            # Кэшируем авторитетные NS-записи (уязвимость: glue без проверки)
            for ns in response.authorities:
                self.cache[f"{ns.name}:{ns.qtype.value}"] = ns
            for glue in response.additional:
                if glue.qtype == QType.A:
                    self.cache[f"{glue.name}:{QType.A.value}"] = glue
                    print(f"  [RESOLVER] Кэширована glue: {glue.name} -> {glue.rdata}")

            # Если в ответе есть искомая A-запись — успех
            for ans in response.answers:
                if ans.qtype == qtype:
                    print(f"  [RESOLVER] Получен ответ: {ans.rdata}")
                    self.cache[cache_key] = ans
                    return ans.rdata

            # Иначе — идём по делегации (NS-запись)
            next_ns = None
            for ns in response.authorities:
                if ns.qtype == QType.NS:
                    # Ищем glue для этого NS
                    glue_key = f"{ns.rdata}:{QType.A.value}"
                    if glue_key in self.cache:
                        next_ns = self.cache[glue_key]
                        break

            if next_ns:
                # Имитируем переход на следующий сервер
                current_server = AuthoritativeServer(next_ns.rdata, next_ns.rdata, {"ns": next_ns.rdata})
            else:
                print(f"  [RESOLVER] Нет glue для продолжения")
                return None

    async def _send_query(self, server, msg: DNSMessage):
        """Симуляция отправки запроса (с возможностью перехвата атакующим)"""
        # В реальности: UDP-пакет
        await asyncio.sleep(0.01)  # имитация RTT
        return server.handle_query(msg)

# ========== Злоумышленник (атака Каминского) ==========
class KaminskyAttacker:
    def __init__(self, target_zone: str, fake_ns_ip: str, real_zone_server: AuthoritativeServer):
        self.target_zone = target_zone  # например, "vu.nl"
        self.fake_ns_ip = fake_ns_ip
        self.real_server = real_zone_server
        self.poison_sent = False

    async def launch_attack(self, resolver: LocalResolver, victim_domain: str):
        """
        Симуляция атаки:
        1. Посылаем множество запросов на несуществующие поддомены
        2. Внедряем поддельные ответы с фальшивой glue-записью
        """
        print(f"\n[ATTACKER] Начинаю атаку на зону {self.target_zone}")
        print(f"[ATTACKER] Цель: заставить резолвер кэшировать {self.target_zone} -> {self.fake_ns_ip}")

        # Генерируем случайные поддомены
        for attempt in range(10):  # для демонстрации — 10 попыток
            random_sub = ''.join(random.choices(string.ascii_lowercase, k = 8))
            bogus_domain = f"{random_sub}.{self.target_zone}"

            # Резолвер начинает легитимный запрос
            print(f"\n[ATTACKER] Попытка {attempt + 1}: запрос на {bogus_domain}")

            # В реальности: атакующий слушает порт и шлёт поддельные ответы быстрее реального
            # Здесь симуляция: создаём поддельный ответ
            fake_response = DNSMessage(
                tx_id = random.randint(0, 65535),  # нужно угадать ID — в симуляции просто берём
                source_port = resolver.pending_requests.get((bogus_domain, QType.A, 0), (0,))[0] if resolver.pending_requests else 12345,
                query_name = bogus_domain,
                query_type = QType.A,
                is_authoritative = True,
                is_recursive_desired = False
            )

            # Добавляем реальные NS-записи (чтобы не вызвать подозрений)
            for ns_name, _ in self.real_server.ns_records.items():
                fake_response.authorities.append(DNSRecord(name = self.target_zone, qtype = QType.NS, ttl = 3600, rdata = ns_name))

            # *** КЛЮЧЕВОЙ МОМЕНТ: поддельная glue-запись ***
            fake_response.additional.append(DNSRecord(name = ns_name, qtype = QType.A, ttl = 3600, rdata = self.fake_ns_ip))
            print(f"  [ATTACKER] Отправляю поддельный ответ: glue {ns_name} -> {self.fake_ns_ip}")

            # Симуляция: если резолвер примет этот ответ, он отравит кэш
            # В реальности нужно угадать ID запроса и порт, обогнать реальный ответ
            # Для демонстрации считаем, что на 5-й попытке успех
            if attempt >= 4:
                print(f"  [ATTACKER] УСПЕХ! Резолвер принял поддельный ответ")
                # Отравляем кэш напрямую (в реальности резолвер сам бы закэшировал)
                resolver.cache[f"{ns_name}:{QType.A.value}"] = DNSRecord(name = ns_name, qtype = QType.A, ttl = 3600, rdata = self.fake_ns_ip)
                resolver.cache[f"{self.target_zone}:{QType.NS.value}"] = DNSRecord(name = self.target_zone, qtype = QType.NS, ttl = 3600, rdata = ns_name)
                self.poison_sent = True
                break
            else:
                print(f"  [ATTACKER] Неудача (не угадан ID/порт)")

        if self.poison_sent:
            print(f"\n[ATTACKER] Зона {self.target_zone} отравлена!")
            print(f"[ATTACKER] Теперь любой запрос к *. {self.target_zone} пойдёт на {self.fake_ns_ip}")
        else:
            print(f"\n[ATTACKER] Атака не удалась (симуляция требует больше попыток)")

# ========== Демонстрация ==========
async def main():
    print("=" * 60)
    print("ДЕМОНСТРАЦИЯ АТАКИ КАМИНСКОГО (учебная симуляция)")
    print("=" * 60)

    # 1. Реальный авторитетный сервер для .nl (с настоящими NS и glue)
    real_ns = {
        "ns1.vu.nl": "192.0.2.10",
        "ns2.vu.nl": "192.0.2.11"
    }
    real_server = AuthoritativeServer(".nl", "203.0.113.1", real_ns)

    # 2. Корневой сервер (делегирует .nl)
    root_server = AuthoritativeServer(".", "198.51.100.1", {".nl": "203.0.113.1"})

    # 3. Локальный резолвер
    resolver = LocalResolver(root_server)

    # 4. Злоумышленник (хочет отравить vu.nl, подставляя свой IP 203.0.113.99)
    attacker = KaminskyAttacker(
        target_zone = "vu.nl",
        fake_ns_ip = "203.0.113.99",  # IP сервера злоумышленника
        real_zone_server = real_server
    )

    # 5. До атаки — нормальный запрос
    print("\n--- ДО АТАКИ ---")
    ip = await resolver.resolve("www.cs.vu.nl", QType.A, 53001)
    print(f"Результат: www.cs.vu.nl -> {ip} (должен быть настоящий IP)")

    # 6. Проводим атаку
    await attacker.launch_attack(resolver, "www.cs.vu.nl")

    # 7. После атаки — снова запрос
    print("\n--- ПОСЛЕ АТАКИ ---")
    ip2 = await resolver.resolve("mail.vu.nl", QType.A, 53002)
    print(f"Результат: mail.vu.nl -> {ip2}")

    if ip2 == "203.0.113.99":
        print("\n[!!!] УСПЕШНОЕ ОТРАВЛЕНИЕ! Резолвер перенаправлен на сервер злоумышленника.")
    else:
        print("\n[INFO] Атака в этой симуляции требует подбора ID. В реальности — десятки тысяч попыток.")

    print("\n" + "=" * 60)
    print("КЛЮЧЕВЫЕ ВЫВОДЫ:")
    print("1. Уязвимость — в принятии glue-записей без проверки.")
    print("2. Атака работает через запросы на НЕСУЩЕСТВУЮЩИЕ поддомены.")
    print("3. Защита: случайные порты (source port randomization) + DNSSEC.")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())