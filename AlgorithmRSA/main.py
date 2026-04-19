import random
import math

# ---------- Вспомогательные функции ----------
def is_prime(n, k = 10):
    """Проверка числа на простоту (тест Миллера-Рабина)"""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    
    # Записываем n-1 = d * 2^r
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    def check(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        return False
    
    for _ in range(k):
        a = random.randrange(2, n - 1)
        if not check(a):
            return False
    return True

def generate_prime(bits):
    """Генерация простого числа заданной битовой длины"""
    while True:
        num = random.getrandbits(bits)
        # Устанавливаем старший бит в 1 и делаем число нечетным
        num |= (1 << bits - 1) | 1
        if is_prime(num):
            return num

def gcd(a, b):
    """Алгоритм Евклида для НОД"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Расширенный алгоритм Евклида (возвращает x, y, gcd)"""
    if b == 0:
        return 1, 0, a
    x1, y1, g = extended_gcd(b, a % b)
    return y1, x1 - (a // b) * y1, g

def mod_inverse(e, z):
    """Обратное число по модулю: e * x ≡ 1 (mod z)"""
    x, y, g = extended_gcd(e, z)
    if g != 1:
        raise ValueError("Обратного элемента не существует")
    return x % z

# ---------- Основной класс RSA ----------
class RSA:
    def __init__(self, key_bits = 1024):
        """
        key_bits - битовая длина простых чисел p и q.
        В реальности n будет ~2*key_bits бит.
        """
        self.key_bits = key_bits
        self.p = None
        self.q = None
        self.n = None
        self.z = None
        self.e = None
        self.d = None
    
    def generate_keys(self):
        """Генерация открытого и закрытого ключей"""
        # Шаг 1: выбираем два больших простых числа p и q
        print(f"Генерация простого числа p ({self.key_bits} бит)...")
        self.p = generate_prime(self.key_bits)
        print(f"Генерация простого числа q ({self.key_bits} бит)...")
        self.q = generate_prime(self.key_bits)
        
        # Шаг 2: вычисляем n = p * q и z = (p-1)*(q-1)
        self.n = self.p * self.q
        self.z = (self.p - 1) * (self.q - 1)
        
        # Шаг 3: выбираем e (обычно 65537) - взаимно простое с z
        # Для простоты используем стандартное значение e = 65537
        # Если оно не взаимно просто с z, пробуем другие
        self.e = 65537
        if gcd(self.e, self.z) != 1:
            # Если 65537 не подходит, ищем другое e
            self.e = random.randrange(2, self.z)
            while gcd(self.e, self.z) != 1:
                self.e = random.randrange(2, self.z)
        
        # Шаг 4: находим d, такое что e*d ≡ 1 (mod z)
        print("Вычисление d...")
        self.d = mod_inverse(self.e, self.z)
        
        print(f"Ключи сгенерированы.")
        return (self.e, self.n), (self.d, self.n)
    
    def encrypt_block(self, plaintext_num):
        """Шифрование одного числового блока: C = P^e mod n"""
        return pow(plaintext_num, self.e, self.n)
    
    def decrypt_block(self, ciphertext_num):
        """Расшифрование одного числового блока: P = C^d mod n"""
        return pow(ciphertext_num, self.d, self.n)
    
    def encrypt_message(self, message):
        """
        Шифрование строки.
        Сообщение разбивается на блоки, каждый блок < n.
        Возвращает список зашифрованных чисел.
        """
        # Определяем максимальный размер блока в байтах
        max_block_bytes = (self.n.bit_length() - 1) // 8
        if max_block_bytes < 1:
            max_block_bytes = 1
        
        # Преобразуем строку в байты
        data = message.encode('utf-8')
        blocks = []
        
        # Разбиваем на блоки
        for i in range(0, len(data), max_block_bytes):
            block_bytes = data[i:i + max_block_bytes]
            # Превращаем блок в число (big-endian)
            block_num = int.from_bytes(block_bytes, 'big')
            if block_num >= self.n:
                raise ValueError(f"Блок {block_num} >= n! Увеличьте размер ключа.")
            encrypted = self.encrypt_block(block_num)
            blocks.append(encrypted)
        
        return blocks
    
    def decrypt_message(self, encrypted_blocks):
        """Расшифровка списка чисел в строку"""
        max_block_bytes = (self.n.bit_length() - 1) // 8
        if max_block_bytes < 1:
            max_block_bytes = 1
        
        decrypted_bytes = bytearray()
        
        for block_num in encrypted_blocks:
            decrypted_num = self.decrypt_block(block_num)
            # Преобразуем число обратно в байты
            # Вычисляем, сколько байт реально нужно для этого числа
            byte_length = (decrypted_num.bit_length() + 7) // 8
            if byte_length == 0:
                byte_length = 1
            block_bytes = decrypted_num.to_bytes(byte_length, 'big')
            decrypted_bytes.extend(block_bytes)
        
        return decrypted_bytes.decode('utf-8')

# ---------- Пример из текста: p=3, q=11 ----------
def example_from_text():
    print("\n" + "=" * 50)
    print("ПРИМЕР ИЗ ТЕКСТА: p=3, q=11")
    print("=" * 50)
    
    class SmallRSA:
        def __init__(self):
            self.p = 3
            self.q = 11
            self.n = 33
            self.z = 20
            self.d = 7
            self.e = mod_inverse(7, 20)  # = 3
        
        def encrypt_block(self, num):
            return pow(num, self.e, self.n)
        
        def decrypt_block(self, num):
            return pow(num, self.d, self.n)
    
    rsa_small = SmallRSA()
    print(f"p = 3, q = 11, n = {rsa_small.n}, z = {rsa_small.z}, d = 7, e = {rsa_small.e}")
    
    # Шифруем слово SUZANNE (как в тексте)
    word = "SUZANNE"
    print(f"\nИсходное слово: {word}")
    
    # Преобразуем буквы в числа по правилу A=1...Z=26
    nums = [ord(ch) - ord('A') + 1 for ch in word]
    print(f"Числа: {nums}")
    
    # Шифруем каждый символ отдельно
    encrypted = [rsa_small.encrypt_block(num) for num in nums]
    print(f"Зашифрованные числа: {encrypted}")
    
    # Расшифровываем
    decrypted_nums = [rsa_small.decrypt_block(c) for c in encrypted]
    decrypted_word = ''.join(chr(num + ord('A') - 1) for num in decrypted_nums)
    print(f"Расшифрованное слово: {decrypted_word}")
    
    # Проверка
    assert decrypted_word == word, "Ошибка расшифровки!"
    print("✓ Расшифровка успешна!")

# ---------- Пример с генерацией ключей ----------
def example_with_key_generation():
    print("\n" + "=" * 50)
    print("ПРИМЕР С ГЕНЕРАЦИЕЙ КЛЮЧЕЙ (128 бит для p и q, n ~ 256 бит)")
    print("=" * 50)
    
    # Для демонстрации берем небольшие ключи (128 бит)
    # В реальности нужно 1024+ бит для p и q
    rsa = RSA(key_bits = 128)  # p и q по 128 бит, n ~ 256 бит (только для демо!)
    pub_key, priv_key = rsa.generate_keys()
    print(f"Открытый ключ (e, n): ({pub_key[0]}, n = {pub_key[1]})")
    print(f"Закрытый ключ (d, n): ({priv_key[0]}, n = {priv_key[1]})")
    print(f"n в битах: {rsa.n.bit_length()}")
    print(f"Максимальный размер блока: {(rsa.n.bit_length() - 1) // 8} байт")
    
    # Сообщение
    message = "SUZANNE"
    print(f"\nСообщение: {message}")
    
    try:
        # Шифрование
        encrypted = rsa.encrypt_message(message)
        print(f"Зашифрованные блоки: {encrypted}")
        
        # Расшифровка
        decrypted = rsa.decrypt_message(encrypted)
        print(f"Расшифрованное сообщение: {decrypted}")
        
        assert decrypted == message, "Ошибка расшифровки!"
        print("✓ Расшифровка успешна!")
    except ValueError as e:
        print(f"Ошибка: {e}")
        print("Попробуйте увеличить размер ключа или использовать более короткое сообщение.")
        
        # Демонстрация с более коротким сообщением
        short_message = "HI"
        print(f"\nПробуем с коротким сообщением: {short_message}")
        encrypted = rsa.encrypt_message(short_message)
        decrypted = rsa.decrypt_message(encrypted)
        print(f"Расшифрованное сообщение: {decrypted}")
        assert decrypted == short_message, "Ошибка расшифровки!"
        print("✓ Расшифровка короткого сообщения успешна!")

# ---------- Дополнительный пример с ручным вводом ----------
def manual_example():
    print("\n" + "=" * 50)
    print("РУЧНОЙ ВВОД ДЛЯ ТЕСТИРОВАНИЯ")
    print("=" * 50)
    
    # Используем маленькие простые числа для наглядности
    rsa = RSA()
    rsa.p = 61
    rsa.q = 53
    rsa.n = rsa.p * rsa.q  # 61 * 53 = 3233
    rsa.z = (rsa.p - 1) * (rsa.q - 1)  # 60 * 52 = 3120
    rsa.e = 17  # стандартное значение, взаимно простое с 3120
    rsa.d = mod_inverse(rsa.e, rsa.z)  # 17 * d ≡ 1 mod 3120 -> d = 2753
    
    print(f"p = 61, q = 53")
    print(f"n={rsa.n}, z={rsa.z}")
    print(f"Открытый ключ (e, n): ({rsa.e}, {rsa.n})")
    print(f"Закрытый ключ (d, n): ({rsa.d}, {rsa.n})")
    
    # Шифруем число
    P = 65  # буква 'A' в ASCII
    C = rsa.encrypt_block(P)
    P_decrypted = rsa.decrypt_block(C)
    
    print(f"\nШифрование числа {P}:")
    print(f"Зашифровано: {C}")
    print(f"Расшифровано: {P_decrypted}")
    assert P == P_decrypted, "Ошибка!"
    print("✓ Расшифровка успешна!")

# ---------- Запуск ----------
if __name__ == "__main__":
    # Пример из текста с p=3, q=11
    example_from_text()
    
    # Пример с реальной генерацией ключей
    example_with_key_generation()
    
    # Дополнительный пример с ручным вводом
    manual_example()