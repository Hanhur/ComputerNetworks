import random

# Упрощённая реализация RSA для демонстрации свойства E(D(P)) = D(E(P)) = P
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    # Расширенный алгоритм Евклида
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % m

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def is_prime(n, k = 5):
    # Простая проверка на простоту (для малых чисел)
    if n < 2:
        return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0:
            return n == p
    # Тест Миллера-Рабина (упрощённо)
    d = n-1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits = 8):
    # Для демонстрации используем маленькие простые числа
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits-1) | 1
        if is_prime(n):
            return n

class RSAKeyPair:
    def __init__(self, bits = 8):
        p = generate_prime(bits)
        q = generate_prime(bits)
        self.n = p * q
        phi = (p - 1) * (q - 1)
        self.e = 65537
        self.d = modinv(self.e, phi)
    
    def encrypt(self, m, key = None):
        # Шифрование открытым ключом (e, n)
        if key is None:
            e, n = self.e, self.n
        else:
            e, n = key
        return pow(m, e, n)
    
    def decrypt(self, c, key = None):
        # Расшифрование закрытым ключом (d, n)
        if key is None:
            d, n = self.d, self.n
        else:
            d, n = key
        return pow(c, d, n)
    
    def get_public_key(self):
        return (self.e, self.n)
    
    def get_private_key(self):
        return (self.d, self.n)

def text_to_int(text):
    # Преобразуем строку в число (для простоты - однобайтовые символы)
    res = 0
    for ch in text:
        res = res * 256 + ord(ch)
    return res

def int_to_text(num):
    # Обратное преобразование
    chars = []
    while num > 0:
        chars.append(chr(num % 256))
        num //= 256
    return ''.join(reversed(chars))

# ========== Демонстрация схемы из текста ==========
def main():
    print("=== Генерация ключей ===")
    alice = RSAKeyPair(bits = 8)   # Алиса (подписывающая сторона)
    bob = RSAKeyPair(bits = 8)     # Боб (получатель)
    print(f"Алиса: n = {alice.n}, e = {alice.e}, d = {alice.d}")
    print(f"Боб:   n = {bob.n}, e = {bob.e}, d = {bob.d}")
    
    # Сообщение, которое Алиса хочет подписать
    message = "Купить 100 акций"
    P = text_to_int(message)
    print(f"\nИсходное сообщение: {message} (число: {P})")
    
    # ---- Алиса создаёт подпись: E_Боба( D_Алисы(P) ) ----
    # Шаг 1: D_Алисы(P) — подпись закрытым ключом Алисы
    D_A_P = alice.decrypt(P, key = alice.get_private_key())  # D_A(P)
    # Шаг 2: E_Боба( ... ) — шифруем открытым ключом Боба
    signed_msg = bob.encrypt(D_A_P, key = bob.get_public_key())
    print(f"\nАлиса отправляет Бобу: E_B(D_A(P)) = {signed_msg}")
    
    # ---- Боб получает и проверяет ----
    # Шаг 1: D_Боба(полученное) -> D_A(P)
    decrypted_step1 = bob.decrypt(signed_msg, key = bob.get_private_key())
    # Шаг 2: E_Алисы( D_A(P) ) -> P
    recovered_P = alice.encrypt(decrypted_step1, key = alice.get_public_key())
    recovered_text = int_to_text(recovered_P)
    
    print(f"\nБоб расшифровал своим D_B: {decrypted_step1}")
    print(f"Боб применил E_A: {recovered_P} -> текст: {recovered_text}")
    
    if recovered_text == message:
        print("✅ Боб подтверждает: подпись верна, сообщение от Алисы.")
    else:
        print("❌ Подпись недействительна.")
    
    # ---- Судебная проверка (без секретных ключей!) ----
    print("\n=== Судебная проверка ===")
    # Боб предъявляет: исходное сообщение P и подпись D_A(P)
    # В реальности у судьи есть открытые ключи Е_Алисы
    court_check = alice.encrypt(decrypted_step1, key = alice.get_public_key())
    if court_check == P:
        print("✅ Судья: подпись D_A(P) подлинная, Алиса виновна.")
    else:
        print("❌ Судья: подпись не проходит.")
    
    # ---- Проблема: Алиса сменила ключ ----
    print("\n=== Проблема смены ключа ===")
    alice_new = RSAKeyPair(bits = 8)  # Алиса генерирует новую пару
    print(f"Новый открытый ключ Алисы: e={alice_new.e}, n={alice_new.n}")
    
    court_check_failed = alice_new.encrypt(decrypted_step1, key = alice_new.get_public_key())
    print(f"Проверка старым открытым ключом (новым Алисы): {court_check_failed} (должно быть {P})")
    if court_check_failed != P:
        print("❌ Судья: подпись недействительна. Боб выглядит глупо.")
    
    # ---- Проблема: кража ключа (симулируем) ----
    print("\n=== Проблема кражи ключа ===")
    print("Алиса заявляет: 'У меня украли секретный ключ, это не я подписывала!'")
    print("Если злоумышленник (или Боб) знает D_A, он мог подделать подпись.")
    print("Суд не может однозначно установить виновного.")

if __name__ == "__main__":
    main()