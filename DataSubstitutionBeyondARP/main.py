#!/usr/bin/env python3
"""
Симулятор атаки "дней рождения" на DNS-кэш (Birthday Attack Simulation)
Демонстрирует, как злоумышленник может отравить кэш DNS-сервера,
отправляя множество поддельных ответов без перехвата трафика.
Основано на принципе: при большом количестве запросов и ответов
вероятность совпадения ID становится высокой (парадокс дней рождения).
"""

import random
import time
import threading
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from enum import Enum


class DNSRecordType(Enum):
    """Типы DNS записей"""
    A = 1
    NS = 2
    CNAME = 5


@dataclass
class DNSQuery:
    """DNS запрос от клиента или локального сервера"""
    query_id: int
    domain: str
    source_port: int
    timestamp: float


@dataclass
class DNSResponse:
    """DNS ответ (настоящий или поддельный)"""
    query_id: int
    domain: str
    ip_address: str
    is_fake: bool


class DNSCache:
    """Кэш DNS-сервера - хранит сопоставления домен -> IP"""
    
    def __init__(self):
        self.cache: Dict[str, str] = {}
        self.poisoned: Dict[str, bool] = {}
    
    def add(self, domain: str, ip: str, is_poisoned: bool = False):
        self.cache[domain] = ip
        self.poisoned[domain] = is_poisoned
        print(f"  [КЭШ] {domain} -> {ip} {'(ОТРАВЛЕН!)' if is_poisoned else ''}")
    
    def get(self, domain: str) -> Optional[str]:
        return self.cache.get(domain)
    
    def is_poisoned(self, domain: str) -> bool:
        return self.poisoned.get(domain, False)


class RealDNSServer:
    """
    Настоящий DNS-сервер (вышестоящий).
    Возвращает правильные IP-адреса для доменов.
    """
    
    def __init__(self):
        # Таблица реальных соответствий доменов IP-адресам
        self.real_mappings: Dict[str, str] = {
            "trusted-services.com": "93.184.216.34",
            "bank.example.com": "192.0.2.10",
            "doctor.example.com": "198.51.100.20",
            "example.com": "93.184.216.34",
        }
    
    def resolve(self, domain: str, query_id: int) -> Optional[DNSResponse]:
        """Настоящий сервер отвечает на запрос с правильным IP"""
        if domain in self.real_mappings:
            # Имитация задержки реального сервера
            time.sleep(random.uniform(0.05, 0.15))
            return DNSResponse(
                query_id = query_id,
                domain = domain,
                ip_address = self.real_mappings[domain],
                is_fake = False
            )
        return None


class LocalDNSServer:
    """
    Локальный DNS-сервер (резолвер) с кэшем.
    Уязвим к атаке "дней рождения" - не проверяет источник ответов должным образом.
    """
    
    def __init__(self, real_server: RealDNSServer):
        self.cache = DNSCache()
        self.real_server = real_server
        self.pending_queries: Dict[int, DNSQuery] = {}  # query_id -> запрос
        self.query_counter = 0
        self.lock = threading.Lock()
    
    def query(self, domain: str, client_port: int = 12345) -> Optional[str]:
        """
        Клиент (жертва) запрашивает IP для домена.
        Сервер сначала проверяет кэш, затем отправляет запрос вышестоящему серверу.
        """
        # Проверяем кэш
        cached_ip = self.cache.get(domain)
        if cached_ip:
            print(f"  [ЛОКАЛЬНЫЙ DNS] Кэш: {domain} -> {cached_ip}")
            return cached_ip
        
        # Кэш пуст - нужно разрешить имя у вышестоящего сервера
        query_id = random.randint(1, 65535)
        query = DNSQuery(
            query_id = query_id,
            domain = domain,
            source_port = client_port,
            timestamp = time.time()
        )
        
        with self.lock:
            self.pending_queries[query_id] = query
        
        print(f"  [ЛОКАЛЬНЫЙ DNS] Запрос #{query_id} для {domain} -> вышестоящий DNS")
        
        # Отправляем запрос реальному серверу
        response = self.real_server.resolve(domain, query_id)
        
        with self.lock:
            if query_id in self.pending_queries:
                del self.pending_queries[query_id]
        
        if response:
            self.cache.add(response.domain, response.ip_address, is_poisoned = False)
            return response.ip_address
        
        return None
    
    def receive_response(self, response: DNSResponse) -> bool:
        """
        Получение ответа от вышестоящего DNS-сервера (или от злоумышленника).
        Локальный сервер проверяет только ID запроса и домен.
        Уязвимость: не проверяет исходный порт и IP отправителя.
        """
        with self.lock:
            pending = self.pending_queries.get(response.query_id)
            
            if not pending:
                # Нет ожидающего запроса с таким ID
                return False
            
            if pending.domain != response.domain:
                # Домен не совпадает
                return False
            
            # ВСЕ ПРОВЕРКИ ПРОЙДЕНЫ! Ответ принимается.
            # (В реальности еще проверяется, что ответ пришел с правильного порта,
            # но старая версия BIND этого не делала - уязвимость!)
            
            del self.pending_queries[response.query_id]
            
            # Добавляем в кэш (возможно, отравленный)
            self.cache.add(response.domain, response.ip_address, is_poisoned = response.is_fake)
            return True


class Attacker:
    """
    Злоумышленник, реализующий атаку "дней рождения".
    Не видит трафик жертвы, но может отправлять запросы к локальному DNS-серверу
    и множество поддельных ответов.
    """
    
    def __init__(self, target_domain: str, fake_ip: str):
        self.target_domain = target_domain
        self.fake_ip = fake_ip
        self.attacks_launched = 0
        self.successes = 0
    
    def launch_birthday_attack(self, local_dns: LocalDNSServer, num_queries: int = 400) -> bool:
        """
        Реализует атаку "дней рождения" (Birthday Attack).
        
        Стратегия:
        1. Отправляем много запросов к локальному DNS-серверу для целевого домена.
           Локальный сервер отправляет запросы вышестоящему серверу с разными ID.
        2. Немедленно отправляем множество поддельных ответов с разными ID.
        3. Ждем, пока хотя бы один поддельный ответ совпадет с ожидающим запросом.
        
        Вероятность успеха при N запросах ~= N^2 / (2 * 65536)
        При N=400 вероятность > 100% (теоретически гарантировано совпадение)
        """
        print(f"\n  [АТАКУЮЩИЙ] Запуск атаки 'дней рождения' на домен {self.target_domain}")
        print(f"  [АТАКУЮЩИЙ] Цель: подменить {self.target_domain} -> {self.fake_ip}")
        print(f"  [АТАКУЮЩИЙ] Отправляем {num_queries} запросов и {num_queries} поддельных ответов...")
        
        self.attacks_launched += 1
        
        # Шаг 1: Отправляем множество запросов к локальному DNS-серверу
        # Каждый запрос порождает ожидающий запрос с уникальным ID
        print(f"  [АТАКУЮЩИЙ] -> Отправка {num_queries} запросов к локальному DNS...")
        
        # Запоминаем ID запросов, которые мы инициировали (в реальной атаке они неизвестны)
        # Но здесь мы их не знаем - атакующий не видит ID!
        # Это ключевая особенность: атакующий действует вслепую.
        
        # Отправляем запросы (каждый запрос создает pending entry в локальном DNS)
        for i in range(num_queries):
            local_dns.query(self.target_domain, client_port = 50000 + i)
        
        # Шаг 2: Отправляем поддельные ответы с разными ID
        print(f"  [АТАКУЮЩИЙ] -> Отправка {num_queries} поддельных ответов...")
        
        # Поддельные ответы отправляются НЕМЕДЛЕННО, пытаясь опередить настоящие ответы
        for i in range(num_queries):
            # Генерируем случайный ID для поддельного ответа
            fake_id = random.randint(1, 65535)
            fake_response = DNSResponse(
                query_id = fake_id,
                domain = self.target_domain,
                ip_address = self.fake_ip,
                is_fake = True
            )
            
            # Отправляем подделку локальному DNS-серверу
            accepted = local_dns.receive_response(fake_response)
            
            if accepted:
                self.successes += 1
                print(f"\n  [АТАКУЮЩИЙ] *** УСПЕХ! *** Поддельный ответ с ID={fake_id} принят!")
                print(f"  [АТАКУЮЩИЙ] Кэш DNS-сервера отравлен: {self.target_domain} -> {self.fake_ip}")
                return True
            
            # Небольшая задержка, чтобы не перегружать симуляцию
            if i % 100 == 0:
                time.sleep(0.001)
        
        print(f"  [АТАКУЮЩИЙ] Атака не удалась за {num_queries} попыток.")
        return False
    
    def launch_birthday_attack_batch(self, local_dns: LocalDNSServer, num_queries: int = 300, num_batches: int = 5) -> Dict:
        """
        Запускает несколько попыток атаки и собирает статистику.
        Демонстрирует, что вероятность успеха растет с количеством запросов.
        """
        results = {
            "success": False,
            "attempts": 0,
            "queries_per_attempt": num_queries,
            "success_rate": 0.0
        }
        
        for batch in range(num_batches):
            print(f"\n{'=' * 60}")
            print(f"ПОПЫТКА {batch + 1}/{num_batches}")
            print(f"{'=' * 60}")
            
            # Для каждой попытки нужно "очистить" состояние локального DNS
            # В реальности атакующий просто ждет истечения таймаутов
            new_local_dns = LocalDNSServer(RealDNSServer())
            
            success = self.launch_birthday_attack(new_local_dns, num_queries)
            results["attempts"] += 1
            
            if success:
                results["success"] = True
                break
        
        if results["success"]:
            results["success_rate"] = 1.0
        else:
            # Теоретическая вероятность при N=300: ~300^2/(2*65536) ≈ 0.69
            # При N=400: ~400^2/(2*65536) ≈ 1.22 (гарантия)
            theoretical_prob = (num_queries ** 2) / (2 * 65536)
            results["success_rate"] = min(theoretical_prob, 1.0)
        
        return results


class Victim:
    """Жертва - обычный пользователь, использующий DNS"""
    
    def __init__(self, local_dns: LocalDNSServer):
        self.local_dns = local_dns
    
    def visit_website(self, domain: str) -> str:
        """Пользователь пытается открыть сайт по доменному имени"""
        print(f"\n  [ЖЕРТВА] Пытается открыть {domain}...")
        ip = self.local_dns.query(domain)
        
        if ip:
            print(f"  [ЖЕРТВА] DNS вернул IP: {ip}")
            return ip
        else:
            print(f"  [ЖЕРТВА] Не удалось разрешить домен {domain}")
            return ""


def run_dns_birthday_attack_simulation():
    """
    Главная функция - запускает полную симуляцию атаки "дней рождения"
    """
    print("=" * 70)
    print("СИМУЛЯЦИЯ DNS-АТАКИ 'ДНЕЙ РОЖДЕНИЯ' (Birthday Attack)")
    print("=" * 70)
    print()
    print("Сценарий из текста:")
    print("- Злоумышленник хочет отравить кэш DNS-сервера")
    print("- Он не может прослушивать трафик (не видит ID запросов)")
    print("- Использует 'парадокс дней рождения' для подбора ID вслепую")
    print("- Отправляет множество запросов и множество поддельных ответов")
    print("- Ждет статистического совпадения ID")
    print()
    
    # Создаем компоненты
    real_server = RealDNSServer()
    local_dns = LocalDNSServer(real_server)
    attacker = Attacker(target_domain = "trusted-services.com", fake_ip = "10.0.0.100")
    victim = Victim(local_dns)
    
    # Шаг 1: Нормальное поведение до атаки
    print("\n" + "=" * 50)
    print("1. НОРМАЛЬНАЯ РАБОТА (ДО АТАКИ)")
    print("=" * 50)
    
    ip = victim.visit_website("trusted-services.com")
    print(f"   Результат: {ip} (должен быть настоящий IP: {real_server.real_mappings['trusted-services.com']})")
    
    # Шаг 2: Атака "дней рождения"
    print("\n" + "=" * 50)
    print("2. АТАКА 'ДНЕЙ РОЖДЕНИЯ'")
    print("=" * 50)
    print("\nЗлоумышленник не видит ID запросов локального DNS-сервера.")
    print("Он отправляет 400 запросов и 400 поддельных ответов с разными ID.")
    print("Теория: при N запросах вероятность совпадения ~= N²/(2*65536)")
    print("При N=400: 400²/(2*65536) = 160000/131072 ≈ 1.22 (>100% гарантия)")
    print()
    
    # Запускаем атаку
    success = attacker.launch_birthday_attack(local_dns, num_queries = 400)
    
    # Шаг 3: Проверка результата
    print("\n" + "=" * 50)
    print("3. ПРОВЕРКА РЕЗУЛЬТАТА")
    print("=" * 50)
    
    ip = victim.visit_website("trusted-services.com")
    
    if ip == attacker.fake_ip:
        print("\n" + "!" * 60)
        print("УСПЕХ! Жертва получила ПОДДЕЛЬНЫЙ IP от отравленного DNS-кэша!")
        print(f"Домен trusted-services.com теперь указывает на {attacker.fake_ip} (сервер злоумышленника)")
        print("!" * 60)
        print("\nПоследствия:")
        print("- Жертва думает, что открыла настоящий сайт trusted-services.com")
        print("- Но на самом деле она на сервере злоумышленника")
        print("- Злоумышленник может реализовать атаку 'человек посередине' (MitM)")
    else:
        print("\nАтака не удалась в этой симуляции. Попробуйте увеличить количество запросов.")
    
    # Демонстрация статистики
    print("\n" + "=" * 50)
    print("4. СТАТИСТИЧЕСКАЯ ДЕМОНСТРАЦИЯ")
    print("=" * 50)
    
    print("\nЗапускаем 3 попытки с разным количеством запросов:")
    
    for num_q in [50, 150, 300]:
        print(f"\n--- {num_q} запросов ---")
        attacker_test = Attacker("example.com", "192.168.1.100")
        test_dns = LocalDNSServer(RealDNSServer())
        
        # Простая проверка - одна попытка
        start_time = time.time()
        success_test = attacker_test.launch_birthday_attack(test_dns, num_queries=num_q)
        elapsed = time.time() - start_time
        
        if success_test:
            print(f"  Результат: УСПЕХ за {elapsed:.2f} сек")
        else:
            # Теоретическая вероятность
            prob = (num_q ** 2) / (2 * 65536)
            print(f"  Результат: НЕУДАЧА (теоретическая вероятность успеха: {prob:.1%})")
    
    print("\n" + "=" * 70)
    print("ВЫВОД")
    print("=" * 70)
    print("""
Атака 'дней рождения' демонстрирует, что даже не видя трафика,
злоумышленник может отравить DNS-кэш, используя теорию вероятностей.
    
Защита от такой атаки:
1. Рандомизация исходного порта DNS-запросов
2. Использование DNSSEC (цифровая подпись ответов)
3. Ограничение частоты запросов к одному домену
4. 0x20-encoding (рандомизация регистра символов в доменном имени)
    """)
    
    return success


def demonstrate_birthday_paradox():
    """
    Демонстрирует парадокс дней рождения в чистом виде
    """
    print("\n" + "=" * 70)
    print("ПАРАДОКС ДНЕЙ РОЖДЕНИЯ (Математическая основа атаки)")
    print("=" * 70)
    
    def birthday_probability(n: int) -> float:
        """Вероятность того, что среди n людей хотя бы у двух совпадают дни рождения"""
        prob_no_match = 1.0
        for i in range(n):
            prob_no_match *= (365 - i) / 365
        return 1 - prob_no_match
    
    print("\nВопрос: сколько нужно людей, чтобы вероятность совпадения дней рождения > 50%?")
    print()
    
    for n in [10, 20, 23, 30, 40, 50, 100]:
        prob = birthday_probability(n)
        print(f"  {n:3d} человек -> вероятность совпадения: {prob:.1%}")
    
    print("\n" + "-" * 50)
    print("Применительно к DNS-атаке:")
    print("  65536 возможных ID запросов (вместо 365 дней)")
    print(f"  При N=300 запросов: вероятность совпадения ~= {300 ** 2 / (2 * 65536):.1%}")
    print(f"  При N=400 запросов: вероятность совпадения ~= {400 ** 2 / (2 * 65536):.1%}")
    print("=" * 70)


if __name__ == "__main__":
    print("DNS BIRTHDAY ATTACK SIMULATOR")
    print("Образовательная программа по материалам текста о спуфинге\n")
    
    # Демонстрация парадокса дней рождения
    demonstrate_birthday_paradox()
    
    # Запуск основной симуляции
    print("\n" * 2)
    input("Нажмите Enter для запуска симуляции атаки...")
    
    success = run_dns_birthday_attack_simulation()
    
    print("\n" + "=" * 70)
    if success:
        print("✅ СИМУЛЯЦИЯ ЗАВЕРШЕНА: Атака успешно продемонстрирована")
    else:
        print("⚠️ СИМУЛЯЦИЯ ЗАВЕРШЕНА: Попробуйте увеличить количество запросов")
    print("=" * 70)