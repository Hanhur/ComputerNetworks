#!/usr/bin/env python3
"""
Криптографические демонстрации на основе текста:
- Принцип Керкгоффса (алгоритм открыт, секретен только ключ)
- Шифр подстановки (посимвольное преобразование)
- Код навахо (замена целых слов)
- Демонстрация длины ключа и перебора
"""

import string
import random
from typing import Dict, List

# ============================================================
# 1. ШИФР ПОДСТАНОВКИ (посимвольное преобразование)
#    Алгоритм полностью открыт, секретен только ключ (таблица замены)
# ============================================================

class SubstitutionCipher:
    """
    Шифр простой подстановки.
    Реализует принцип Керкгоффса: алгоритм публичен,
    секретна только таблица подстановки (ключ).
    """
    
    def __init__(self, key: str = None):
        """
        key: строка из 26 уникальных букв (перемешанный алфавит)
        Если key не задан, генерируется случайный ключ.
        """
        self.alphabet = string.ascii_uppercase
        
        if key is None:
            # Генерируем случайный ключ (перемешанный алфавит)
            key_list = list(self.alphabet)
            random.shuffle(key_list)
            self.key = ''.join(key_list)
        else:
            self.key = key.upper()
            
        # Создаём таблицы подстановки
        self.encrypt_table = str.maketrans(self.alphabet, self.key)
        self.decrypt_table = str.maketrans(self.key, self.alphabet)
    
    def encrypt(self, plaintext: str) -> str:
        """Зашифрование открытого текста"""
        plaintext = plaintext.upper()
        return plaintext.translate(self.encrypt_table)
    
    def decrypt(self, ciphertext: str) -> str:
        """Расшифрование зашифрованного текста"""
        ciphertext = ciphertext.upper()
        return ciphertext.translate(self.decrypt_table)
    
    def get_key(self) -> str:
        """Получить ключ (секрет)"""
        return self.key


# ============================================================
# 2. КОД НАВАХО (пример из текста)
#    Замена целых слов (в отличие от посимвольного шифра)
# ============================================================

class NavajoCode:
    """
    Симуляция кода навахо: целые слова заменяются другими словами.
    В реальности использовался язык навахо, здесь - просто замена слов.
    """
    
    def __init__(self):
        # Словарь кодов: военный термин -> кодовое слово (имитация навахо)
        self.codebook = {
            "ТАНК": "ЧЕРЕПАХА",
            "ПРОТИВОТАНКОВОЕ ОРУЖИЕ": "УБИЙЦА ЧЕРЕПАХ",
            "САМОЛЕТ": "ЖЕЛЕЗНАЯ ПТИЦА",
            "ПОДВОДНАЯ ЛОДКА": "ЖЕЛЕЗНАЯ РЫБА",
            "ГЕНЕРАЛ": "БОЛЬШОЙ ВОЖДЬ",
            "СОЛДАТ": "ВОИН",
            "БОМБА": "ГРОМОВОЙ КАМЕНЬ",
            "ПУЛЕМЕТ": "БЫСТРЫЙ ОГОНЬ"
        }
        # Обратный словарь для расшифровки
        self.reverse_codebook = {v: k for k, v in self.codebook.items()}
    
    def encode(self, message: str) -> str:
        """Кодирование сообщения (замена целых слов)"""
        result = message
        for term, code in self.codebook.items():
            result = result.replace(term, code)
        return result
    
    def decode(self, coded_message: str) -> str:
        """Декодирование сообщения"""
        result = coded_message
        for code, term in self.reverse_codebook.items():
            result = result.replace(code, term)
        return result
    
    def get_codebook(self) -> Dict:
        """Кодовая книга (секрет) - но алгоритм замены слов известен"""
        return self.codebook


# ============================================================
# 3. ДЕМОНСТРАЦИЯ ДЛИНЫ КЛЮЧА И ТРУДОЗАТРАТ
#    Экспоненциальный рост сложности перебора
# ============================================================

class KeyStrengthDemo:
    """Демонстрация влияния длины ключа на стойкость"""
    
    @staticmethod
    def brute_force_time_estimate(key_length_bits: int) -> str:
        """
        Оценка времени перебора ключей заданной длины
        при скорости 1 миллиард ключей в секунду
        """
        n_keys = 2 ** key_length_bits
        keys_per_second = 1_000_000_000  # 1 млрд/сек
        
        seconds = n_keys / keys_per_second
        
        if seconds < 60:
            return f"{seconds:.1f} секунд"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} минут"
        elif seconds < 86400:
            return f"{seconds / 3600:.1f} часов"
        elif seconds < 31536000:
            return f"{seconds / 86400:.1f} дней"
        elif seconds < 31536000 * 1000:
            return f"{seconds / 31536000:.1f} лет"
        else:
            return f"{seconds / 31536000 / 1e9:.1f} миллиардов лет"
    
    @staticmethod
    def demonstrate():
        """Показать таблицу трудозатрат для разной длины ключа"""
        print("\n" + "=" * 60)
        print("ДЕМОНСТРАЦИЯ ДЛИНЫ КЛЮЧА И ТРУДОЗАТРАТ")
        print("=" * 60)
        print("Скорость перебора: 1 млрд ключей/сек (гипотетический суперкомпьютер)")
        print("-" * 60)
        
        for bits in [16, 32, 40, 56, 64, 128, 256]:
            time_est = KeyStrengthDemo.brute_force_time_estimate(bits)
            if bits == 64:
                note = " ← достаточно против 'младшего брата'"
            elif bits == 128:
                note = " ← коммерческий уровень"
            elif bits == 256:
                note = " ← защита от спецслужб"
            else:
                note = ""
            
            print(f"Ключ {bits:3d} бит: {2 ** bits:>12,} комбинаций → {time_est:>20}{note}")


# ============================================================
# 4. СИММЕТРИЧНОЕ ШИФРОВАНИЕ (XOR - простейший пример)
#    Используется один ключ для шифрования и дешифрования
# ============================================================

class XORCipher:
    """
    Простейшее симметричное шифрование с помощью XOR.
    Демонстрирует: E_K(D_K(P)) = P
    """
    
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """XOR шифрование (и дешифрование - та же операция)"""
        result = bytearray()
        for i, byte in enumerate(plaintext):
            key_byte = self.key[i % len(self.key)]
            result.append(byte ^ key_byte)
        return bytes(result)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        # XOR симметричен: шифрование и дешифрование одинаковы
        return self.encrypt(ciphertext)
    
    @staticmethod
    def demonstrate():
        print("\n" + "=" * 60)
        print("СИММЕТРИЧНОЕ ШИФРОВАНИЕ (XOR) - Демонстрация")
        print("=" * 60)
        
        # Исходное сообщение
        plaintext = b"SECRET MESSAGE"
        key = b"MYKEY123"  # Ключ известен только отправителю и получателю
        
        cipher = XORCipher(key)
        
        ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(ciphertext)
        
        print(f"Открытый текст:  {plaintext}")
        print(f"Ключ:            {key}")
        print(f"Шифротекст:      {ciphertext.hex()}")
        print(f"Расшифровано:    {decrypted}")
        print(f"Проверка:        {'✓' if decrypted == plaintext else '✗'}")
        print("\nФормула: D_K(E_K(P)) = P — выполняется!")


# ============================================================
# 5. ПРИМЕР ТРЁХ ТИПОВ АТАК (из текста)
# ============================================================

class CryptoAttackDemo:
    """Демонстрация трёх типов атак криптоаналитика"""
    
    @staticmethod
    def demonstrate(cipher: SubstitutionCipher):
        print("\n" + "=" * 60)
        print("ТИПЫ АТАК НА ШИФР")
        print("=" * 60)
        
        secret_message = "HELLO WORLD THIS IS SECRET"
        
        print(f"Исходное сообщение: {secret_message}")
        print(f"Ключ (секретный):   {cipher.get_key()}")
        print("-" * 40)
        
        # 1. Атака только с шифротекстом
        ciphertext = cipher.encrypt(secret_message)
        print(f"1. Только шифротекст:      {ciphertext}")
        print("   (криптоаналитик видит только это)")
        
        # 2. Атака с известным открытым текстом
        known_plaintext = "HELLO"
        known_ciphertext = cipher.encrypt(known_plaintext)
        print(f"2. Известный открытый текст: '{known_plaintext}' → '{known_ciphertext}'")
        print("   (пара даёт информацию о подстановке)")
        
        # 3. Атака с выбранным открытым текстом
        chosen_plaintext = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        chosen_ciphertext = cipher.encrypt(chosen_plaintext)
        print(f"3. Выбранный открытый текст: зашифрован весь алфавит")
        print(f"   → Получена полная таблица подстановки!")
        print(f"   Расшифровка стала тривиальной.")


# ============================================================
# 6. ГЛАВНАЯ ДЕМОНСТРАЦИЯ
# ============================================================

def main():
    print("=" * 70)
    print("КРИПТОГРАФИЧЕСКИЕ ДЕМОНСТРАЦИИ")
    print("На основе принципов из текста:")
    print("  • Принцип Керкгоффса (алгоритм открыт, секретен ключ)")
    print("  • Отличие шифра от кода")
    print("  • Длина ключа и трудозатраты")
    print("  • Три типа атак криптоаналитика")
    print("=" * 70)
    
    # 1. Шифр подстановки (принцип Керкгоффса)
    print("\n" + "=" * 60)
    print("1. ШИФР ПОДСТАНОВКИ (посимвольное преобразование)")
    print("=" * 60)
    
    # Алгоритм полностью открыт, секретен только ключ
    cipher = SubstitutionCipher()
    print(f"Алгоритм: замена каждой буквы по таблице")
    print(f"Секретный ключ: {cipher.get_key()}")
    
    plain = "ATTACK AT DAWN"
    encrypted = cipher.encrypt(plain)
    decrypted = cipher.decrypt(encrypted)
    
    print(f"\nОткрытый текст:  {plain}")
    print(f"Зашифрованный:   {encrypted}")
    print(f"Расшифрованный:  {decrypted}")
    print(f"Успех: {decrypted == plain}")
    
    # 2. Код навахо (замена целых слов)
    print("\n" + "=" * 60)
    print("2. КОД НАВАХО (замена целых слов)")
    print("=" * 60)
    
    navajo = NavajoCode()
    military_msg = "Передайте: ТАНК и ПРОТИВОТАНКОВОЕ ОРУЖИЕ у САМОЛЕТА"
    encoded = navajo.encode(military_msg)
    decoded = navajo.decode(encoded)
    
    print(f"Военное сообщение: {military_msg}")
    print(f"Кодовые слова:     {encoded}")
    print(f"Расшифровано:      {decoded}")
    
    # 3. Демонстрация длины ключа
    KeyStrengthDemo.demonstrate()
    
    # 4. Симметричное шифрование XOR
    XORCipher.demonstrate()
    
    # 5. Типы атак
    CryptoAttackDemo.demonstrate(cipher)
    
    # 6. Дополнительно: почему принцип Керкгоффса важен
    print("\n" + "=" * 60)
    print("ПОЧЕМУ НЕЛЬЗЯ ХРАНИТЬ АЛГОРИТМ В СЕКРЕТЕ?")
    print("=" * 60)
    print(""" 
    Представьте, что вы используете секретный алгоритм. Если:
    1. Вашего сотрудника уволят — он знает алгоритм
    2. Ваше устройство попало в руки врага — алгоритм могут извлечь
    3. Вы хотите использовать продукт в другой стране — алгоритм раскроют
    
    А если алгоритм открыт (как AES), то:
    • Тысячи учёных пытаются его взломать годами
    • Если никто не взломал → можно доверять
    • При компрометации меняете только ключ (короткая строка)
    • А не весь алгоритм (сотни страниц спецификации)
    
    → Это и есть ПРИНЦИП КЕРКГОФФСА (1883 г.)
    """)

if __name__ == "__main__":
    main()