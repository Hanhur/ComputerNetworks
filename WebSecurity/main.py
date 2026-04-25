#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Обучающая программа по веб-безопасности (на основе текста)
ДЕМОНСТРАЦИЯ УГРОЗ - ТОЛЬКО ДЛЯ ОБРАЗОВАТЕЛЬНЫХ ЦЕЛЕЙ
Никакой код не выполняет реальных атак или сбора данных.
"""

import hashlib
import hmac
import secrets
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import urllib.parse
import re


# ============================================================
# ЧАСТЬ 1. Безопасное именование объектов (подмена сайта как в Hotmail)
# ============================================================

@dataclass
class DomainInfo:
    """Информация о домене"""
    name: str
    is_phishing: bool = False
    fake_mirror_of: Optional[str] = None


class DomainValidator:
    """
    Показывает проблему: как пользователь может попасть на поддельный сайт
    (пример из текста: зеркало Hotmail для кражи почты)
    """
    
    def __init__(self):
        # Список известных легитимных доменов
        self.legitimate_domains = {"hotmail.com", "microsoft.com", "google.com"}
        
        # Пример подозрительных доменов (вариации)
        self.suspicious_patterns = [
            (r"hotmail\.com\.", "дополнительная точка перед доменом верхнего уровня"),
            (r"hotmai1\.com", "замена буквы на цифру (1 вместо l)"),
            (r"hotmail\.security\.com", "поддомен, создающий ложное впечатление"),
            (r"hotmail—secure\.com", "использование нестандартного тире"),
        ]
    
    def check_domain(self, url: str) -> Dict:
        """Проверяет домен на признаки фишинга"""
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        is_suspicious = False
        reason = []
        
        # Проверка на точное совпадение с легитимными
        if domain in self.legitimate_domains:
            return {
                "domain": domain,
                "is_legitimate": True,
                "risk": "low",
                "warning": None
            }
        
        # Проверка на известные паттерны подделок
        for pattern, desc in self.suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                is_suspicious = True
                reason.append(f"Подозрительный паттерн: {desc}")
        
        # Проверка на близкие имена (хомографическая атака)
        for legit in self.legitimate_domains:
            if legit in domain and domain != legit:
                is_suspicious = True
                reason.append(f"Домен содержит имя '{legit}' но отличается: {domain}")
        
        return {
            "domain": domain,
            "is_legitimate": False,
            "risk": "high" if is_suspicious else "medium",
            "warning": "; ".join(reason) if reason else "Неизвестный домен — будьте осторожны"
        }
    
    @staticmethod
    def demonstrate_phishing_attack():
        """Демонстрация: как в 1999 году с Hotmail"""
        print("\n" + "=" * 70)
        print("ЧАСТЬ 1: ПРОБЛЕМА ИМЕНОВАНИЯ (как в атаке на Hotmail, 1999)")
        print("=" * 70)
        
        validator = DomainValidator()
        
        # Пример URL, которые может ввести пользователь
        test_urls = [
            "https://hotmail.com",                    # настоящий
            "https://hotmail.com.security-verify.com", # подозрительный
            "https://hotmai1.com",                    # визуально похожий
            "https://secure-hotmail.com",              # ложный поддомен
            "https://microsoft.hotmail-support.net",   # подделка
        ]
        
        print("\n📧 Сценарий: пользователь получает ссылку 'на Hotmail' по email")
        print("Проблема: сложно отличить настоящий сайт от поддельного зеркала\n")
        
        for url in test_urls:
            result = validator.check_domain(url)
            status = "✅ ЛЕГИТИМНЫЙ" if result["is_legitimate"] else "⚠️ ПОДОЗРИТЕЛЬНЫЙ"
            print(f"URL: {url}")
            print(f"  Домен: {result['domain']}")
            print(f"  {status}, риск: {result['risk']}")
            if result["warning"]:
                print(f"  Предупреждение: {result['warning']}")
            print()


# ============================================================
# ЧАСТЬ 2. Безопасность соединений (кража кредиток)
# ============================================================

class ConnectionSecurityDemo:
    """
    Демонстрация важности защищённых соединений (пример кражи 300 000 кредиток)
    Показывает, почему нужен TLS/HTTPS
    """
    
    @staticmethod
    def simulate_insecure_connection():
        """Симуляция перехвата незащищённого соединения"""
        print("\n" + "=" * 70)
        print("ЧАСТЬ 2: НЕЗАЩИЩЁННОЕ СОЕДИНЕНИЕ (кража кредиток, как у Максима)")
        print("=" * 70)
        
        print("""
💳 Сценарий: интернет-магазин передаёт данные карты по HTTP (без шифрования)
        
[Клиент] -----(номер карты: 4111-1111-1111-1111)----> [Интернет]
                ↑                                       
                │                                      
        [Злоумышленник перехватывает трафик]
                │
                └───> УКРАДЕНО: 4111-1111-1111-1111
        """)
        
        # Демонстрация: что такое "соль" для паролей и почему хранение в открытом виде опасно
        # (в тексте: Максим украл номера 300 000 карт с сайта магазина)
        
        print("🔓 Как это работает:")
        print("1. Клиент вводит данные карты на сайте (HTTP, без HTTPS)")
        print("2. Злоумышленник в той же Wi-Fi сети перехватывает пакеты")
        print("3. Данные видны в открытом виде (plain text)")
        print()
        
        print("🛡️ Решение: HTTPS / TLS")
        print("   - Все данные шифруются")
        print("   - Даже при перехвате злоумышленник видит бессмысленный шифротекст")
        print("   - Дополнительно: сертификаты проверяют подлинность сервера")
    
    @staticmethod
    def demonstrate_safe_secure_string(password: str) -> Tuple[str, str]:
        """
        Демонстрация: даже в базе данных пароли/номера карт
        нельзя хранить в открытом виде (пример кражи 300 000 карт)
        """
        # Соль для защиты от радужных таблиц
        salt = secrets.token_hex(16)
        
        # Хеширование пароля с солью (необратимо)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        
        return salt, hashed.hex()
    
    @staticmethod
    def demonstrate_storage_problem():
        print("\n💾 Проблема хранения данных:")
        print("Взломщик Максим украл базу с номерами кредиток в открытом виде.")
        print("Как надо было хранить (хотя бы хеши/токены):")
        
        test_cc = "4532-1234-5678-9012"
        salt, hash_val = ConnectionSecurityDemo.demonstrate_safe_secure_string(test_cc)
        print(f"  Исходный номер: {test_cc} (НЕ хранить в БД!)")
        print(f"  Соль: {salt[:16]}...")
        print(f"  Хеш: {hash_val[:32]}...")
        print("  🛡️ Даже если украдут БД — восстановить номера почти невозможно")


# ============================================================
# ЧАСТЬ 3. Исполняемый код на клиенте (XSS, подмена страниц)
# ============================================================

class ClientSideCodeDemo:
    """
    Демонстрация опасности исполняемого кода на клиенте
    (дефейс сайтов — как Yahoo, CIA, NASA)
    """
    
    @staticmethod
    def simulate_xss_vulnerability():
        """Симуляция XSS-атаки (подмена содержимого)"""
        print("\n" + "=" * 70)
        print("ЧАСТЬ 3: ИСПОЛНЯЕМЫЙ КОД НА КЛИЕНТЕ (дефейс Yahoo, CIA, NASA)")
        print("=" * 70)
        
        # Пример комментария на форуме (уязвимом)
        malicious_comment = """
        <script>
            // Злой код: заменяет содержимое страницы на "Взломано!"
            document.body.innerHTML = '<h1 style="color:red">Site Defaced by Cracker</h1>';
            // Также может украсть куки и отправить злоумышленнику
        </script>
        Отличный пост!
        """
        
        print("🐍 Сценарий: пользователь оставляет комментарий на форуме")
        print(f"Комментарий (вводит злоумышленник):\n{malicious_comment[:100]}...\n")
        
        print("⚠️ Если сайт НЕ экранирует HTML:")
        print("  Браузер выполнит <script> и подменит содержимое страницы")
        print("  Результат: посетители видят 'Взломано!' вместо контента")
        print("  Именно так происходил дефейс сайтов Yahoo, CIA, NASA\n")
        
        print("🛡️ Защита: Content Security Policy (CSP), экранирование вывода")
        print("  Например: замена <script> на &lt;script&gt;")
    
    @staticmethod
    def simulate_csp_demo():
        """Демонстрация CSP (политики безопасности контента)"""
        print("\n🛡️ Пример CSP-заголовка:")
        print("Content-Security-Policy: default-src 'self'; script-src 'none'")
        print("  => Запрещено выполнение ЛЮБЫХ скриптов из сторонних источников")
        print("  Даже если злоумышленник вставит <script> — он не выполнится")


# ============================================================
# БОНУС: DDoS (из текста про Yahoo и другие)
# ============================================================

class DDoSDemo:
    """Демонстрация принципа DDoS-атаки (образовательно)"""
    
    @staticmethod
    def explain_ddos():
        print("\n" + "=" * 70)
        print("БОНУС: DDoS-АТАКА (из текста о Yahoo и серверах США)")
        print("=" * 70)
        
        print("""
🌐 Принцип DDoS (Distributed Denial of Service):
   
   [Ботнет из взломанных компьютеров]
          │     │     │
          └─────┼─────┘
                ▼
          [Целевой сервер]
          (например, Yahoo)

1. Злоумышленник управляет тысячами заражённых машин (ботнет)
2. Все они одновременно шлют запросы к одному серверу
3. Сервер не справляется с нагрузкой и перестаёт отвечать
4. Результат: сайт недоступен для обычных пользователей

Из текста: "Такие атаки настолько распространены, что уже перестали быть новостью"
        """)
        print("🛡️ Защита: распределённые серверы, капчи, балансировка нагрузки, фильтрация трафика")


# ============================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================

def main():
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║   ОБУЧАЮЩАЯ ПРОГРАММА: ВЕБ-БЕЗОПАСНОСТЬ   ║")
    print("║   По мотивам текста о трёх типах угроз     ║")
    print("╚" + "═" * 68 + "╝")
    
    # Часть 1: Именование и фишинг (Hotmail, 1999)
    DomainValidator.demonstrate_phishing_attack()
    
    # Часть 2: Соединения и кража данных
    ConnectionSecurityDemo.simulate_insecure_connection()
    ConnectionSecurityDemo.demonstrate_storage_problem()
    
    # Часть 3: Исполняемый код
    ClientSideCodeDemo.simulate_xss_vulnerability()
    ClientSideCodeDemo.simulate_csp_demo()
    
    # Бонус: DDoS
    DDoSDemo.explain_ddos()
    
    print("\n" + "=" * 70)
    print("📌 ВАЖНО:")
    print("• Эта программа НЕ выполняет реальных атак")
    print("• Она показывает ПРИНЦИПЫ уязвимостей из вашего текста")
    print("• Для реальной безопасности используйте: HTTPS, CSP, санитизацию ввода")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()