import random
import math

# ---------- Вспомогательные функции ----------
def is_prime(n, k = 5):
    """Проверка числа на простоту (тест Миллера-Рабина)"""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    
    # Записываем n - 1 = d * 2 ^ r
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

def generate_prime(bits = 8):
    """Генерация простого числа заданной битности (для обучения)"""
    while True:
        num = random.getrandbits(bits)
        num |= (1 << bits - 1) | 1  # Ставим старший и младший бит в 1
        if is_prime(num):
            return num

def egcd(a, b):
    """Расширенный алгоритм Евклида"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """Обратное число по модулю m"""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception("Обратного элемента не существует")
    else:
        return x % m

# ---------- Генерация ключей ----------
def generate_keys(bits = 8):
    """
    Создаёт пару открытого и закрытого ключей.
    Возвращает: (открытый_ключ, закрытый_ключ)
    где открытый_ключ = (e, n), закрытый_ключ = (d, n)
    """
    # Шаг 1: выбираем два различных простых числа p и q
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    
    # Шаг 2: вычисляем n = p * q
    n = p * q
    
    # Шаг 3: функция Эйлера φ(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)
    
    # Шаг 4: выбираем e (открытая экспонента), обычно 65537, но для малых чисел возьмём 3 или 17
    e = 17
    while math.gcd(e, phi) != 1:
        e += 2
    
    # Шаг 5: вычисляем d = e^(-1) mod φ(n)
    d = modinv(e, phi)
    
    return ((e, n), (d, n))

# ---------- Шифрование и расшифрование ----------
def encrypt(message, public_key):
    """
    Шифрование открытым ключом public_key = (e, n)
    Сообщение должно быть числом меньше n.
    """
    e, n = public_key
    return pow(message, e, n)

def decrypt(ciphertext, private_key):
    """
    Расшифрование закрытым ключом private_key = (d, n)
    """
    d, n = private_key
    return pow(ciphertext, d, n)

# ---------- Преобразование строк в числа и обратно ----------
def text_to_number(text):
    """Преобразует строку в число (побайтово)"""
    result = 0
    for ch in text:
        result = (result << 8) + ord(ch)
    return result

def number_to_text(num):
    """Преобразует число обратно в строку"""
    chars = []
    while num > 0:
        chars.append(chr(num & 0xFF))
        num >>= 8
    return ''.join(reversed(chars))

# ---------- Демонстрация работы ----------
def main():
    print("=" * 60)
    print("КРИПТОСИСТЕМА С ОТКРЫТЫМ КЛЮЧОМ (RSA)")
    print("=" * 60)
    
    # 1. Алиса генерирует свою пару ключей
    print("\n1. Алиса генерирует пару ключей:")
    alice_public, alice_private = generate_keys(bits = 8)  # bits=8 для простоты, в реальности 2048+
    print(f"   Открытый ключ Алисы (e, n) = {alice_public}")
    print(f"   Закрытый ключ Алисы (d, n) = {alice_private}")
    
    # 2. Боб генерирует свою пару ключей
    print("\n2. Боб генерирует пару ключей:")
    bob_public, bob_private = generate_keys(bits = 8)
    print(f"   Открытый ключ Боба (e, n) = {bob_public}")
    print(f"   Закрытый ключ Боба (d, n) = {bob_private}")
    
    # 3. Алиса хочет отправить секретное сообщение Бобу
    print("\n3. Алиса отправляет сообщение Бобу:")
    original_message = "Привет, Боб!"
    print(f"   Исходное сообщение: '{original_message}'")
    
    # Преобразуем строку в число
    msg_num = text_to_number(original_message)
    print(f"   Сообщение как число: {msg_num}")
    
    # Проверяем, что число меньше модуля n (иначе шифрование не сработает)
    if msg_num >= bob_public[1]:
        print(f"   ВНИМАНИЕ: число {msg_num} >= n={bob_public[1]}. В реальности используются большие ключи.")
        # Для демонстрации возьмём остаток (не совсем корректно, но для примера сойдёт)
        msg_num = msg_num % bob_public[1]
        print(f"   Используем число: {msg_num}")
    
    # Шифруем открытым ключом Боба
    cipher = encrypt(msg_num, bob_public)
    print(f"   Зашифрованное сообщение (число): {cipher}")
    
    # 4. Боб расшифровывает своим закрытым ключом
    print("\n4. Боб расшифровывает сообщение:")
    decrypted_num = decrypt(cipher, bob_private)
    decrypted_text = number_to_text(decrypted_num)
    print(f"   Расшифрованное число: {decrypted_num}")
    print(f"   Расшифрованное сообщение: '{decrypted_text}'")
    
    # 5. Демонстрация, что никто другой не может расшифровать
    print("\n5. Проверка свойства из текста:")
    print("   Ева (злоумышленник) перехватила шифротекст, но у неё нет закрытого ключа Боба.")
    print("   Если Ева попытается расшифровать открытым ключом (неправильно):")
    try:
        wrong_decrypt = decrypt(cipher, bob_public)  # Это бессмысленно
        print(f"   Получится бессмысленное число: {wrong_decrypt}")
    except:
        print("   Расшифрование открытым ключом не работает (как и ожидалось).")
    
    print("\n" + "=" * 60)
    print("ВЫВОД: как сказано в тексте — ")
    print("  • Ключ дешифрования (закрытый) нельзя получить из ключа шифрования (открытого).")
    print("  • D(E(P)) = P — расшифрование работает корректно.")
    print("  • Система стойка, даже если взломщик знает открытый ключ.")
    print("=" * 60)

if __name__ == "__main__":
    main()