#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mod_security эмулятор на Python
Анализирует HTTP-запросы по правилам, аналогичным Apache mod_security
"""

import re
import json
import logging
import sys
import io
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import unquote
from dataclasses import dataclass
from enum import Enum

# Настройка кодировки для Windows
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding = 'utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding = 'utf-8')


class Action(Enum):
    """Действия при срабатывании правила"""
    ALLOW = "allow"
    DENY = "deny"
    REDIRECT = "redirect"
    LOG_ONLY = "log_only"
    EXEC = "exec"


@dataclass
class SecurityRule:
    """Правило безопасности (аналог SecFilter/SecRule)"""
    id: int
    pattern: str
    description: str
    action: Action
    redirect_url: Optional[str] = None
    exec_script: Optional[str] = None
    is_regex: bool = True
    case_sensitive: bool = False
    phases: List[int] = None  # 1: запрос, 2: тело, 3: заголовки
    
    def __post_init__(self):
        if self.phases is None:
            self.phases = [1, 2, 3]
        flags = 0 if self.case_sensitive else re.IGNORECASE
        self.compiled_pattern = re.compile(self.pattern, flags)


class ModSecurityEngine:
    """
    Движок безопасности HTTP-запросов
    Аналог mod_security для Apache
    """
    
    def __init__(self, audit_log_file: str = "modsec_audit.log"):
        self.rules: List[SecurityRule] = []
        self.audit_log_file = audit_log_file
        self.request_counter = 0
        
        # Настройка логирования с поддержкой UTF-8
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Обработчик для файла (UTF-8)
        file_handler = logging.FileHandler(audit_log_file, encoding = 'utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Обработчик для консоли (с кодировкой)
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # Форматтер
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Отключаем propagation, чтобы избежать дублирования
        self.logger.propagate = False
        
        # Добавляем правила после настройки логирования
        self.setup_default_rules()
    
    def setup_default_rules(self):
        """
        Установка правил по умолчанию (аналогично SecFilter из статьи)
        """
        default_rules = [
            # Защита от доступа к системным файлам
            SecurityRule(1001, r"/etc/passwd | /etc/shadow", "Access to passwd/shadow file", Action.DENY),
            
            # Защита от выполнения системных команд
            SecurityRule(1002, r"/bin/(ls | cat | rm | cp | ftp | wget | curl)", "System command execution", Action.DENY),
            
            # Path traversal атака (../)
            SecurityRule(1003, r"\.\./", "Path traversal attack", Action.DENY),
            
            # SQL-инъекции
            SecurityRule(2001, r"delete\s + from", "SQL DELETE injection", Action.DENY),
            SecurityRule(2002, r"insert\s + into", "SQL INSERT injection", Action.DENY),
            SecurityRule(2003, r"select. + from", "SQL SELECT injection", Action.DENY),
            SecurityRule(2004, r"union\s + select", "SQL UNION injection", Action.DENY),
            SecurityRule(2005, r"or\s + 1\s * =\s * 1", "SQL always true attack", Action.DENY),
            SecurityRule(2006, r"drop\s + table", "SQL DROP TABLE attack", Action.DENY),
            
            # XSS атаки
            SecurityRule(3001, r"<script[^>] * >", "XSS script tag", Action.DENY),
            SecurityRule(3002, r"javascript:", "XSS javascript protocol", Action.DENY),
            SecurityRule(3003, r"onload = | onclick = | onerror = ", "XSS event handler", Action.DENY),
            SecurityRule(3004, r"<[^>] * on\w + =", "XSS inline event", Action.DENY),
            
            # Защита от кодированных атак (%13 и т.д.)
            SecurityRule(4001, r"%[0-1][0-9a-fA-F]", "Invalid characters (codes <32)", Action.DENY),
            SecurityRule(4002, r"%7F | %[8-9A-F][0-9A-F]", "Invalid characters (>126 ASCII)", Action.DENY),
            
            # Защита от инъекций в заголовках
            SecurityRule(5001, r"\r\n", "HTTP response splitting", Action.DENY),
            
            # Дополнительные атаки
            SecurityRule(6001, r"\$\{. * \}", "JNDI injection (Log4Shell)", Action.DENY),
            SecurityRule(6002, r"file:// | gopher://", "Unsafe protocols", Action.DENY),
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
    
    def add_rule(self, rule: SecurityRule):
        """Добавление правила безопасности"""
        self.rules.append(rule)
        self.logger.info(f"Added rule #{rule.id}: {rule.description}")
    
    def check_byte_range(self, text: str, min_byte: int = 32, max_byte: int = 126) -> bool:
        """
        Проверка диапазона байтов (аналог SecFilterForceByteRange)
        Возвращает True если все символы допустимы
        """
        for char in text:
            code = ord(char)
            if code < min_byte or code > max_byte:
                # Пропускаем символы \n и \r в теле запроса
                if char in ['\n', '\r', '\t']:
                    continue
                self.logger.warning(f"Invalid character: '{repr(char)}' (code {code})")
                return False
        return True
    
    def check_url_encoding(self, url: str) -> bool:
        """
        Проверка корректности URL-кодировки
        Аналог SecFilterCheckURLEncoding
        """
        # Проверяем наличие %XX и пытаемся декодировать
        if re.search(r'%[0-9a-fA-F]{2}', url):
            try:
                unquote(url)
                return True
            except:
                self.logger.warning(f"Invalid URL encoding: {url}")
                return False
        return True
    
    def analyze_request(self, method: str, path: str, headers: Dict, body: str = "") -> Tuple[bool, List[str]]:
        """
        Анализ HTTP-запроса
        
        Returns:
            (allowed, triggered_rules): разрешен ли запрос и какие правила сработали
        """
        self.request_counter += 1
        triggered_rules = []
        
        # Декодируем URL
        decoded_path = unquote(path)
        
        # 1. Проверка диапазона байтов
        if not self.check_byte_range(path + body):
            rule_id = "BYTE_RANGE"
            triggered_rules.append("Byte range violation (32-126)")
            self.log_audit(method, path, headers, body, False, [rule_id])
            return False, triggered_rules
        
        # 2. Проверка URL-кодировки
        if not self.check_url_encoding(path):
            rule_id = "URL_ENCODING"
            triggered_rules.append("Invalid URL encoding")
            self.log_audit(method, path, headers, body, False, [rule_id])
            return False, triggered_rules
        
        # 3. Объединяем все данные для проверки
        all_data = f"{method} {decoded_path}\n"
        for key, value in headers.items():
            all_data += f"{key}: {value}\n"
        all_data += body
        
        # 4. Проверка по правилам
        for rule in self.rules:
            if rule.compiled_pattern.search(all_data):
                triggered_rules.append(f"#{rule.id}: {rule.description}")
                
                # Выполняем действие
                if rule.action == Action.DENY:
                    self.log_audit(method, path, headers, body, False, triggered_rules)
                    return False, triggered_rules
                
                elif rule.action == Action.REDIRECT and rule.redirect_url:
                    self.logger.info(f"Redirecting to {rule.redirect_url}")
                    self.log_audit(method, path, headers, body, True, triggered_rules)
                    return True, triggered_rules
                
                elif rule.action == Action.EXEC and rule.exec_script:
                    self.execute_script(rule.exec_script, method, path, body)
        
        # 5. Если все проверки пройдены
        self.log_audit(method, path, headers, body, True, [])
        return True, []
    
    def execute_script(self, script_path: str, method: str, path: str, body: str):
        """Выполнение внешнего скрипта при срабатывании правила (аналог exec:)"""
        try:
            import subprocess
            subprocess.Popen([script_path, method, path, body], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
            self.logger.info(f"Executed script: {script_path}")
        except Exception as e:
            self.logger.error(f"Error executing script {script_path}: {e}")
    
    def log_audit(self, method: str, path: str, headers: Dict, body: str, allowed: bool, triggered_rules: List[str]):
        """
        Логирование аудита (аналог SecAuditLog)
        """
        audit_entry = {
            "timestamp": datetime.now().isoformat(),
            "request_id": self.request_counter,
            "method": method,
            "path": path,
            "headers": headers,
            "body": body[:500],  # Ограничиваем размер для лога
            "allowed": allowed,
            "triggered_rules": triggered_rules,
            "decision": "ALLOWED" if allowed else "BLOCKED"
        }
        
        self.logger.info(f"Request #{self.request_counter}: {method} {path} -> {audit_entry['decision']}")
        
        if triggered_rules:
            self.logger.warning(f"Triggered rules: {', '.join(triggered_rules)}")
        
        # Пишем детальный лог в файл (уже в UTF-8 через file_handler)
        # Дополнительно сохраняем в JSON формате
        with open(self.audit_log_file + ".json", "a", encoding = "utf-8") as f:
            f.write(json.dumps(audit_entry, ensure_ascii = False) + "\n")


class HTTPServerEmulator:
    """Эмулятор веб-сервера с интегрированной mod_security защитой"""
    
    def __init__(self, security_engine: ModSecurityEngine):
        self.security = security_engine
    
    def handle_request(self, raw_request: str) -> Dict:
        """
        Обработка HTTP-запроса с проверкой безопасности
        
        Returns:
            Результат обработки с кодом статуса и сообщением
        """
        lines = raw_request.strip().split('\n')
        if not lines:
            return {"status": 400, "message": "Bad Request", "allowed": False}
        
        # Парсим первую строку (метод, путь, версия)
        request_line = lines[0].split(' ')
        if len(request_line) < 2:
            return {"status": 400, "message": "Bad Request", "allowed": False}
        
        method = request_line[0]
        path = request_line[1]
        
        # Парсим заголовки
        headers = {}
        body = ""
        body_start = False
        
        for line in lines[1:]:
            if line.strip() == "":
                body_start = True
                continue
            
            if not body_start:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            else:
                body += line + "\n"
        
        # Проверяем запрос через security engine (аналог mod_security)
        allowed, triggered = self.security.analyze_request(method, path, headers, body)
        
        if not allowed:
            return {
                "status": 406,  # Not Acceptable (аналог status:406 из статьи)
                "message": "Request blocked by security module",
                "allowed": False,
                "triggered_rules": triggered
            }
        
        # Симуляция обработки запроса (если разрешен)
        return {
            "status": 200,
            "message": "OK",
            "allowed": True,
            "triggered_rules": [],
            "response": self.generate_response(method, path)
        }
    
    def generate_response(self, method: str, path: str) -> str:
        """Генерация ответа для разрешенных запросов"""
        if path == "/":
            return "<html><body><h1>Welcome!</h1><p>Your request was approved by mod_security</p></body></html>"
        else:
            return f"<html><body><h1>Path: {path}</h1><p>Request processed successfully</p></body></html>"


# Пример использования
def main():
    print("=" * 60)
    print("ModSecurity Emulator for Python")
    print("Analog of Apache security module")
    print("=" * 60)
    
    # Инициализация движка безопасности
    security = ModSecurityEngine("modsec_audit.log")
    
    # Добавление пользовательских правил (как в статье)
    security.add_rule(SecurityRule(
        id = 9999, 
        pattern = r"admin | administrator",
        description = "Access to admin panel",
        action = Action.REDIRECT,
        redirect_url = "http://localhost/blocked.html"
    ))
    
    security.add_rule(SecurityRule(
        id = 9998,
        pattern = r"attack | hack | exploit",
        description = "Attack attempt detected",
        action = Action.LOG_ONLY
    ))
    
    # Создание веб-сервера эмулятора
    server = HTTPServerEmulator(security)
    
    # Тестовые запросы
    test_requests = [
        # Normal request
        "GET /index.html HTTP/1.1\nHost: example.com\n\n",
        
        # Access to /etc/passwd
        "GET /../../etc/passwd HTTP/1.1\nHost: example.com\n\n",
        
        # SQL injection
        "GET /login?user=admin&pass=' OR '1'='1 HTTP/1.1\nHost: example.com\n\n",
        
        # XSS attack
        "POST /comment HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\ncomment=<script>alert('XSS')</script>",
        
        # Command execution attempt
        "GET /cgi-bin/test?cmd=/bin/ls HTTP/1.1\nHost: example.com\n\n",
        
        # Path traversal
        "GET /download?file=../config.php HTTP/1.1\nHost: example.com\n\n",
        
        # Encoded attack via %00
        "GET /file.php%00.jpg HTTP/1.1\nHost: example.com\n\n",
    ]
    
    print("\n[INFO] Starting request testing...\n")
    
    for i, req in enumerate(test_requests, 1):
        print(f"\n{'─' * 50}")
        print(f"Test #{i}:")
        print(f"Request: {req.split(chr(10))[0]}")
        
        result = server.handle_request(req)
        
        if result["allowed"]:
            print(f"✅ RESULT: ALLOWED (Status: {result['status']})")
        else:
            print(f"❌ RESULT: BLOCKED (Status: {result['status']})")
            if result.get("triggered_rules"):
                print(f"   Triggered rules:")
                for rule in result["triggered_rules"]:
                    print(f"   - {rule}")
    
    print(f"\n{'=' * 60}")
    print(f"Testing completed. Audit saved to 'modsec_audit.log'")
    print(f"Total requests checked: {security.request_counter}")
    
    # Statistics
    try:
        with open("modsec_audit.log.json", "r", encoding="utf-8") as f:
            logs = f.readlines()
            blocked = sum(1 for log in logs if '"allowed": false' in log)
            print(f"Blocked requests: {blocked}")
            print(f"Allowed requests: {security.request_counter - blocked}")
    except FileNotFoundError:
        print("Log file not created yet")


if __name__ == "__main__":
    main()