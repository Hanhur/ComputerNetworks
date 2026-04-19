# #!/usr/bin/env python3
# # -*- coding: utf-8 -*-
# """
# Демонстрация алгоритмов с открытым ключом на основе текста:
# - Рюкзак Меркла-Хеллмана (и его взлом)
# - Эль-Гамаль (дискретные логарифмы)
# - Эллиптические кривые (сравнение сложности)
# """

# import random
# import math
# from typing import List, Tuple

# # ============================================================
# # 1. АЛГОРИТМ РЮКЗАКА МЕРКЛА-ХЕЛЛМАНА (ВЗЛАМЫВАЕМЫЙ)
# # ============================================================

# class MerkleHellmanKnapsack:
#     """
#     Рюкзачный криптоалгоритм Меркла-Хеллмана.
#     НЕ ИСПОЛЬЗОВАТЬ НА ПРАКТИКЕ — взломан Шамиром и Ривестом!
#     """
    
#     def __init__(self, bits: int = 8):
#         self.bits = bits
#         self.private_key = None
#         self.public_key = None
#         self._generate_keys()
    
#     def _generate_superincreasing(self) -> List[int]:
#         """Генерирует сверхвозрастающую последовательность (легкая задача)"""
#         seq = []
#         total = 0
#         for _ in range(self.bits):
#             next_val = total + random.randint(1, 5)
#             seq.append(next_val)
#             total += next_val
#         return seq
    
#     def _generate_keys(self):
#         """Генерирует пару ключей: приватный (сверхвозрастающий) и публичный (маскированный)"""
#         superinc = self._generate_superincreasing()
        
#         # Выбираем модуль m > сумма всех элементов
#         m = sum(superinc) + random.randint(10, 100)
        
#         # Выбираем множитель w, взаимно простой с m
#         w = random.randint(2, m - 1)
#         while math.gcd(w, m) != 1:
#             w = random.randint(2, m - 1)
        
#         # Создаем публичный ключ: b_i = (w * a_i) mod m
#         public = [(w * a) % m for a in superinc]
        
#         self.private_key = {
#             'superincreasing': superinc,
#             'm': m,
#             'w': w,
#             'w_inv': pow(w, -1, m)  # обратное по модулю m
#         }
#         self.public_key = public
    
#     def encrypt(self, message: int) -> int:
#         """Шифрует число, представляя его как битовую маску"""
#         if message >= (1 << self.bits):
#             raise ValueError(f"Сообщение слишком большое (макс {self.bits} бит)")
        
#         cipher = 0
#         for i in range(self.bits):
#             if (message >> i) & 1:
#                 cipher += self.public_key[i]
#         return cipher
    
#     def decrypt(self, cipher: int) -> int:
#         """Расшифровывает, используя секретную сверхвозрастающую последовательность"""
#         # Убираем маскировку: c' = (c * w^(-1)) mod m
#         c_prime = (cipher * self.private_key['w_inv']) % self.private_key['m']
        
#         # Решаем задачу рюкзака для сверхвозрастающей последовательности (просто жадным алгоритмом)
#         message = 0
#         remaining = c_prime
#         for i in reversed(range(self.bits)):
#             if remaining >= self.private_key['superincreasing'][i]:
#                 remaining -= self.private_key['superincreasing'][i]
#                 message |= (1 << i)
        
#         if remaining != 0:
#             # Это может случиться при ошибке или если cipher был подделан
#             return -1
#         return message
    
#     def demonstrate_weakness(self):
#         """Демонстрирует, почему алгоритм уязвим (атака LLL — упрощённая иллюстрация)"""
#         print("\n  [!] УЯЗВИМОСТЬ РЮКЗАЧНОГО АЛГОРИТМА:")
#         print("  Ади Шамир и Рон Ривест взломали его, восстановив")
#         print("  сверхвозрастающую последовательность из публичного ключа.")
#         print("  Современные методы (LLL-алгоритм) делают взлом быстрым.")
#         print("  Поэтому алгоритм НЕ используется на практике.\n")


# # ============================================================
# # 2. АЛГОРИТМ ЭЛЬ-ГАМАЛЯ (ДИСКРЕТНЫЕ ЛОГАРИФМЫ)
# # ============================================================

# class ElGamal:
#     """
#     Криптосистема Эль-Гамаля на основе сложности дискретного логарифма.
#     Безопасна при правильном выборе параметров.
#     """
    
#     @staticmethod
#     def is_prime(n: int, k: int = 5) -> bool:
#         """Простая проверка на простоту (Миллер-Рабин)"""
#         if n < 2:
#             return False
#         for p in [2, 3, 5, 7, 11, 13]:
#             if n % p == 0:
#                 return n == p
#         d = n - 1
#         s = 0
#         while d % 2 == 0:
#             d //= 2
#             s += 1
#         for _ in range(k):
#             a = random.randint(2, n - 1)
#             x = pow(a, d, n)
#             if x == 1 or x == n - 1:
#                 continue
#             for _ in range(s - 1):
#                 x = pow(x, 2, n)
#                 if x == n - 1:
#                     break
#             else:
#                 return False
#         return True
    
#     @staticmethod
#     def find_primitive_root(p: int) -> int:
#         """Находит первообразный корень по модулю p (для малых p)"""
#         if p == 2:
#             return 1
#         # Разложение p-1 на простые множители (упрощённо)
#         phi = p - 1
#         factors = set()
#         n = phi
#         for i in range(2, int(math.sqrt(n)) + 1):
#             if n % i == 0:
#                 factors.add(i)
#                 while n % i == 0:
#                     n //= i
#         if n > 1:
#             factors.add(n)
        
#         for g in range(2, p):
#             ok = True
#             for q in factors:
#                 if pow(g, phi // q, p) == 1:
#                     ok = False
#                     break
#             if ok:
#                 return g
#         return -1
    
#     def __init__(self, bits: int = 16):
#         """Генерирует ключи для заданной битности простого числа"""
#         self.bits = bits
#         # Генерируем простое число p
#         while True:
#             p = random.getrandbits(bits)
#             p |= (1 << bits - 1) | 1  # делаем нечётным и нужной длины
#             if self.is_prime(p):
#                 self.p = p
#                 break
        
#         self.g = self.find_primitive_root(self.p)
#         if self.g == -1:
#             self.g = 2  # fallback
        
#         self.private_key = random.randint(2, self.p - 2)
#         self.public_key = pow(self.g, self.private_key, self.p)
    
#     def encrypt(self, message: int) -> Tuple[int, int]:
#         """Шифрует сообщение: (g^k mod p, m * y^k mod p)"""
#         if message >= self.p:
#             raise ValueError(f"Сообщение должно быть меньше p = {self.p}")
        
#         k = random.randint(2, self.p - 2)
#         c1 = pow(self.g, k, self.p)
#         c2 = (message * pow(self.public_key, k, self.p)) % self.p
#         return (c1, c2)
    
#     def decrypt(self, cipher: Tuple[int, int]) -> int:
#         """Расшифровывает: m = c2 * (c1^priv)^(-1) mod p"""
#         c1, c2 = cipher
#         s = pow(c1, self.private_key, self.p)
#         s_inv = pow(s, -1, self.p)
#         return (c2 * s_inv) % self.p


# # ============================================================
# # 3. ЭЛЛИПТИЧЕСКИЕ КРИВЫЕ (УПРОЩЁННАЯ ДЕМОНСТРАЦИЯ)
# # ============================================================

# class SimpleEllipticCurve:
#     """
#     Максимально упрощённая демонстрация идеи эллиптических кривых.
#     Реальная ECC работает с конечными полями и более сложной арифметикой.
#     """
    
#     def __init__(self, a: int = -1, b: int = 1):
#         self.a = a
#         self.b = b
#         self.discriminant = 4 * a * a * a + 27 * b * b  # для проверки невырожденности
    
#     @staticmethod
#     def energy_comparison():
#         """Сравнение энергозатрат по Ленстре (из вашего текста)"""
#         print("\n  🌊 ЭНЕРГЕТИЧЕСКОЕ СРАВНЕНИЕ (Арьен Ленстра):")
#         print("  • 228-битный RSA-ключ:  ~ энергия для кипячения 1 чайной ложки воды")
#         print("  • 228-битный ECC-ключ:  ~ энергия для кипячения ВСЕЙ воды на планете")
#         print("  Вывод: даже испарив всю воду (включая воду в телах),")
#         print("         взломщики ECC вряд ли добьются успеха.\n")
    
#     def explain_complexity(self):
#         """Объясняет, почему DLP на эллиптической кривой сложнее"""
#         print("\n  📐 ПОЧЕМУ ECC СТОЙКЕЕ:")
#         print("  - Для RSA: субэкспоненциальные атаки (решето числового поля)")
#         print("  - Для ECC: только экспоненциальные атаки (ρ-метод Полларда)")
#         print("  - Это означает, что 256-битная ECC ~ 3072-битный RSA по стойкости")
#         print("  - Поэтому ECC эффективнее для мобильных устройств и IoT\n")


# # ============================================================
# # 4. ДЕМОНСТРАЦИОННАЯ ФУНКЦИЯ
# # ============================================================

# def main():
#     print("=" * 70)
#     print("🔐 АЛГОРИТМЫ С ОТКРЫТЫМ КЛЮЧОМ")
#     print("   На основе текста: Рюкзак, Эль-Гамаль, Эллиптические кривые")
#     print("=" * 70)
    
#     # --------------------------------------------------------
#     # 1. Рюкзак Меркла-Хеллмана
#     # --------------------------------------------------------
#     print("\n📦 1. АЛГОРИТМ РЮКЗАКА (Меркл-Хеллман, 1978)")
#     print("-" * 50)
    
#     knapsack = MerkleHellmanKnapsack(bits = 8)
#     print(f"  Публичный ключ (рюкзак): {knapsack.public_key}")
#     print(f"  Приватный ключ (сверхвозрастающий): {knapsack.private_key['superincreasing']}")
    
#     # Шифруем сообщение
#     message = 0b10101101  # 173 в десятичной
#     print(f"\n  Исходное сообщение (биты): {bin(message)}")
    
#     cipher = knapsack.encrypt(message)
#     print(f"  Зашифрованный рюкзак (сумма): {cipher}")
    
#     decrypted = knapsack.decrypt(cipher)
#     print(f"  Расшифрованное сообщение: {bin(decrypted)}")
    
#     knapsack.demonstrate_weakness()
    
#     # --------------------------------------------------------
#     # 2. Эль-Гамаль
#     # --------------------------------------------------------
#     print("\n🔢 2. АЛГОРИТМ ЭЛЬ-ГАМАЛЯ (1985)")
#     print("   Сложность: дискретный логарифм в конечном поле")
#     print("-" * 50)
    
#     elgamal = ElGamal(bits=16)
#     print(f"  Простое p = {elgamal.p}")
#     print(f"  Первообразный корень g = {elgamal.g}")
#     print(f"  Публичный ключ y = {elgamal.public_key}")
    
#     secret_msg = 12345
#     print(f"\n  Сообщение: {secret_msg}")
    
#     encrypted = elgamal.encrypt(secret_msg)
#     print(f"  Зашифровано (c1, c2) = {encrypted}")
    
#     decrypted_msg = elgamal.decrypt(encrypted)
#     print(f"  Расшифровано: {decrypted_msg}")
    
#     # --------------------------------------------------------
#     # 3. Эллиптические кривые
#     # --------------------------------------------------------
#     print("\n📐 3. ЭЛЛИПТИЧЕСКИЕ КРИВЫЕ (Menezes & Vanstone, 1993)")
#     print("-" * 50)
    
#     ecc = SimpleEllipticCurve(a = -1, b = 1)
#     print(f"  Кривая: y² = x³ + {ecc.a}x + {ecc.b}")
#     print(f"  Дискриминант: {ecc.discriminant} (≠0 → невырожденная)")
    
#     ecc.energy_comparison()
#     ecc.explain_complexity()
    
#     # --------------------------------------------------------
#     # Итоговое резюме
#     # --------------------------------------------------------
#     print("\n" + "=" * 70)
#     print("📌 ИТОГОВЫЙ ВЫВОД (на основе вашего текста):")
#     print("  ✅ Алгоритм рюкзака — ИСТОРИЧЕСКИЙ ИНТЕРЕС, взломан")
#     print("  ✅ RSA, Эль-Гамаль — основаны на сложных задачах")
#     print("  ✅ Эллиптические кривые — лучшая стойкость на бит")
#     print("  ✅ Энергетический аргумент Ленстры: ECC ≈ вода планеты")
#     print("=" * 70)


# if __name__ == "__main__":
#     main()

# =================================================================================================================

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Рюкзачный алгоритм Меркла-Хеллмана + ДЕМОНСТРАЦИЯ ВЗЛОМА
На основе текста: почему алгоритм имеет криптостойкость НОЛЬ
"""

import random
import math
from typing import List, Tuple, Optional

# ============================================================
# РЮКЗАЧНЫЙ АЛГОРИТМ (РАБОЧАЯ ВЕРСИЯ, НО НЕБЕЗОПАСНАЯ)
# ============================================================

class MerkleHellmanKnapsack:
    """
    Рюкзачный криптоалгоритм Меркла-Хеллмана.
    РАБОТАЕТ, НО КРИПТОСТОЙКОСТЬ = 0
    """
    
    def __init__(self, bits: int = 8):
        self.bits = bits
        self.private_key = None
        self.public_key = None
        self._generate_keys()
    
    def _generate_superincreasing(self) -> List[int]:
        """Сверхвозрастающая последовательность (каждый элемент > суммы предыдущих)"""
        seq = []
        total = 0
        for _ in range(self.bits):
            next_val = total + random.randint(1, 10)
            seq.append(next_val)
            total += next_val
        return seq
    
    def _generate_keys(self):
        """Генерация пары ключей"""
        superinc = self._generate_superincreasing()
        
        # m > сумма всех элементов
        m = sum(superinc) + random.randint(10, 100)
        
        # w, взаимно простое с m
        w = random.randint(2, m - 1)
        while math.gcd(w, m) != 1:
            w = random.randint(2, m - 1)
        
        # Публичный ключ: b_i = w * a_i mod m
        public = [(w * a) % m for a in superinc]
        
        self.private_key = {
            'superincreasing': superinc,
            'm': m,
            'w': w,
            'w_inv': pow(w, -1, m)
        }
        self.public_key = public
    
    def encrypt(self, message: int) -> int:
        """Шифрование: сумма выбранных публичных элементов"""
        if message >= (1 << self.bits):
            raise ValueError(f"Сообщение должно быть в {self.bits} битах")
        
        total = 0
        for i in range(self.bits):
            if (message >> i) & 1:
                total += self.public_key[i]
        return total
    
    def decrypt(self, cipher: int) -> int:
        """Расшифровка через обратное преобразование"""
        # Убираем маскировку
        c_prime = (cipher * self.private_key['w_inv']) % self.private_key['m']
        
        # Жадный алгоритм для сверхвозрастающей последовательности
        message = 0
        remaining = c_prime
        for i in range(self.bits - 1, -1, -1):
            if remaining >= self.private_key['superincreasing'][i]:
                remaining -= self.private_key['superincreasing'][i]
                message |= (1 << i)
        
        return message if remaining == 0 else -1


# ============================================================
# АТАКА НА РЮКЗАЧНЫЙ АЛГОРИТМ
# ============================================================

class KnapsackAttack:
    """
    Демонстрация атаки на рюкзак Меркла-Хеллмана.
    
    Для малых размеров (бит <= 20) можно решить задачу о подмножестве
    через meet-in-the-middle. Это показывает, почему алгоритм ненадёжен.
    
    Реальная атака Шамира/Ривеста использует LLL-алгоритм,
    который работает даже для больших битов.
    """
    
    @staticmethod
    def subset_sum_meet_in_the_middle(numbers: List[int], target: int) -> Optional[int]:
        """
        Решает задачу о подмножестве: найти битовую маску,
        сумма выбранных элементов = target.
        
        Сложность: O(2^(n/2)) вместо O(2^n)
        """
        n = len(numbers)
        if n > 25:
            return None  # слишком долго для демо
        
        # Разделяем на две половины
        half = n // 2
        
        # Первая половина: все суммы и соответствующие маски
        left_sums = {}
        for mask in range(1 << half):
            s = 0
            for i in range(half):
                if mask & (1 << i):
                    s += numbers[i]
            left_sums[s] = mask
        
        # Вторая половина
        right_numbers = numbers[half:]
        right_len = len(right_numbers)
        
        for mask in range(1 << right_len):
            s = 0
            for i in range(right_len):
                if mask & (1 << i):
                    s += right_numbers[i]
            
            need = target - s
            if need in left_sums:
                # Комбинируем маски
                left_mask = left_sums[need]
                final_mask = left_mask | (mask << half)
                return final_mask
        
        return None
    
    @staticmethod
    def attack_knapsack(knapsack: MerkleHellmanKnapsack, ciphertext: int) -> Tuple[int, bool]:
        """
        Пытается взломать рюкзак, зная только публичный ключ и шифртекст.
        Возвращает (расшифрованное сообщение, успех_атаки)
        """
        public_key = knapsack.public_key
        
        # Решаем задачу о подмножестве
        mask = KnapsackAttack.subset_sum_meet_in_the_middle(public_key, ciphertext)
        
        if mask is not None:
            return mask, True
        
        return 0, False
    
    @staticmethod
    def demonstrate_attack():
        """Полная демонстрация атаки"""
        print("\n  🔓 ДЕМОНСТРАЦИЯ ВЗЛОМА РЮКЗАЧНОГО АЛГОРИТМА")
        print("  --------------------------------------------------")
        
        # Создаём рюкзак
        knapsack = MerkleHellmanKnapsack(bits = 12)  # 12 бит достаточно для демо
        print(f"  Публичный ключ (известен всем): {knapsack.public_key}")
        
        # Шифруем секретное сообщение
        secret_message = random.randint(0, (1 << 12) - 1)
        ciphertext = knapsack.encrypt(secret_message)
        
        print(f"  Секретное сообщение: {secret_message} (биты: {bin(secret_message)})")
        print(f"  Шифртекст (сумма): {ciphertext}")
        
        # Атака
        print("\n  🔨 НАЧАЛО АТАКИ (Meet-in-the-Middle)")
        print("  Злоумышленник знает только публичный ключ и шифртекст.")
        
        recovered, success = KnapsackAttack.attack_knapsack(knapsack, ciphertext)
        
        if success:
            print(f"  ✅ АТАКА УСПЕШНА! Восстановлено сообщение: {recovered}")
            if recovered == secret_message:
                print("  ✅ Сообщение совпадает с оригиналом → ПОЛНЫЙ ВЗЛОМ")
            else:
                print(f"  ⚠️ Восстановлено другое сообщение (коллизия): {recovered}")
        else:
            print("  ❌ Атака не удалась (только для малых битов)")


# ============================================================
# ПОЧЕМУ РЕАЛЬНЫЙ ВЗЛОМ ЕЩЁ ПРОЩЕ (ИДЕЯ LLL)
# ============================================================

class LLLIdeaDemo:
    """
    Объяснение идеи LLL-атаки Шамира и Ривеста без сложной математики
    """
    
    @staticmethod
    def explain():
        print("\n  🧠 ПОЧЕМУ РЮКЗАК ЛЕГКО ВЗЛОМАТЬ (идея Шамира/Ривеста):")
        print("  ------------------------------------------------------")
        print("  1. Публичный ключ: b_i = (w * a_i) mod m")
        print("  2. Секретные параметры: a_i (сверхвозрастающие), w, m")
        print("  3. Идея атаки: найти w и m, чтобы b_i стали сверхвозрастающими")
        print("  4. LLL-алгоритм находит короткий вектор в решётке,")
        print("     который соответствует сверхвозрастающей последовательности")
        print("  5. Это превращает 'сложную' задачу рюкзака в 'лёгкую'")
        print()
        print("  📌 ИТОГ: даже улучшенные версии были взломаны")
        print("     Шамир (первая версия) → Ривест (вторая версия)")
        print("     Адлеман не получил награду — Меркл испугался $10,000")
        print("     Сегодня рюкзачные схемы НЕ ИСПОЛЬЗУЮТСЯ")


# ============================================================
# ОСНОВНАЯ ДЕМОНСТРАЦИЯ
# ============================================================

def main():
    print("=" * 70)
    print("🎒 РЮКЗАЧНЫЙ АЛГОРИТМ МЕРКЛА-ХЕЛЛМАНА")
    print("   Работает, но криптостойкость = 0")
    print("=" * 70)
    
    # 1. Нормальная работа
    print("\n📦 1. НОРМАЛЬНАЯ РАБОТА АЛГОРИТМА")
    print("-" * 50)
    
    knapsack = MerkleHellmanKnapsack(bits = 8)
    print(f"  Приватный ключ (сверхвозрастающий): {knapsack.private_key['superincreasing']}")
    print(f"  Публичный ключ: {knapsack.public_key}")
    
    msg = 0b10101101
    cipher = knapsack.encrypt(msg)
    decrypted = knapsack.decrypt(cipher)
    
    print(f"  Сообщение: {bin(msg)} → шифр: {cipher} → расшифровано: {bin(decrypted)}")
    print("  ✅ Алгоритм работает корректно")
    
    # 2. Демонстрация взлома
    KnapsackAttack.demonstrate_attack()
    
    # 3. Объяснение реальной атаки
    LLLIdeaDemo.explain()
    
    # 4. Ссылка на текст
    print("\n" + "=" * 70)
    print("📖 ИСТОРИЧЕСКАЯ СПРАВКА (из вашего текста):")
    print("  • Меркл предложил $100 за взлом → Шамир взломал")
    print("  • Меркл усилил → $1000 → Ривест взломал")
    print("  • Меркл испугался предлагать $10,000 (Адлеман остался без награды)")
    print("=" * 70)
    print("\n⚠️ ВЫВОД: Алгоритм имеет ИСТОРИЧЕСКОЕ значение,")
    print("   но НЕ используется на практике из-за полной уязвимости.")


if __name__ == "__main__":
    main()