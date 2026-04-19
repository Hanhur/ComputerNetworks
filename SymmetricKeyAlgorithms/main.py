"""
Программа, демонстрирующая принципы современной криптографии:
- P-блок (перестановка битов)
- S-блок (подстановка)
- Продукционный шифр (каскад раундов)
На основе принципов, описанных в тексте.
"""

import random

# ------------------------------------------------------------
# 1. P-БЛОК (PERMUTATION) - перестановка битов
# ------------------------------------------------------------
class PBlock:
    """
    P-блок выполняет перестановку битов входного сообщения.
    Пример из текста: вход 01234567 -> выход 36071245
    """
    
    def __init__(self, permutation):
        """
        permutation: список, где индекс - новая позиция бита,
                     значение - откуда взять бит.
                     Например, [3,6,0,7,1,2,4,5] означает:
                     бит 0 на выходе = бит 3 на входе
                     бит 1 на выходе = бит 6 на входе и т.д.
        """
        self.permutation = permutation
        self.size = len(permutation)
    
    def permute(self, bits):
        """
        bits: список битов (0/1) длиной self.size
        возвращает переставленный список битов
        """
        if len(bits) != self.size:
            raise ValueError(f"Длина входа {len(bits)} не равна размеру P-блока {self.size}")
        result = [bits[self.permutation[i]] for i in range(self.size)]
        return result
    
    def __str__(self):
        return f"P-блок (перестановка): {self.permutation}"


# ------------------------------------------------------------
# 2. S-БЛОК (SUBSTITUTION) - табличная подстановка
# ------------------------------------------------------------
class SBlock:
    """
    S-блок выполняет подстановку: заменяет входное значение
    на выходное по таблице замен.
    Пример из текста: 01234567 -> 24506713
    (т.е. 0->2, 1->4, 2->5, 3->0, 4->6, 5->7, 6->1, 7->3)
    """
    
    def __init__(self, substitution_table, input_bits, output_bits):
        """
        substitution_table: словарь {входное_число: выходное_число}
        input_bits: количество бит на входе
        output_bits: количество бит на выходе
        """
        self.substitution_table = substitution_table
        self.input_bits = input_bits
        self.output_bits = output_bits
        self.input_max = 1 << input_bits  # 2^input_bits
        self.output_max = 1 << output_bits
    
    def substitute(self, value):
        """
        value: целое число от 0 до 2^input_bits - 1
        возвращает целое число от 0 до 2^output_bits - 1
        """
        if value not in self.substitution_table:
            raise ValueError(f"Значение {value} не найдено в таблице подстановки")
        return self.substitution_table[value]
    
    def substitute_bits(self, bits):
        """
        bits: список битов (длиной input_bits)
        возвращает список битов (длиной output_bits)
        """
        # Преобразуем биты в число
        value = 0
        for b in bits:
            value = (value << 1) | b
        
        # Подстановка
        substituted = self.substitute(value)
        
        # Преобразуем обратно в список битов
        result = []
        for i in range(self.output_bits - 1, -1, -1):
            result.append((substituted >> i) & 1)
        return result
    
    def __str__(self):
        return f"S-блок ({self.input_bits}->{self.output_bits}): {self.substitution_table}"


# ------------------------------------------------------------
# 3. ПРОДУКЦИОННЫЙ ШИФР (PRODUCT CIPHER)
# Каскад из раундов, каждый раунд содержит S-блоки и P-блок
# ------------------------------------------------------------
class ProductCipher:
    """
    Продукционный шифр, как описано в тексте:
    - Вход разбивается на группы
    - Каждая группа обрабатывается S-блоком
    - Затем P-блок перемешивает результат
    - Процесс повторяется несколько раундов
    """
    
    def __init__(self, s_blocks, p_block, rounds = 4):
        """
        s_blocks: список S-блоков (по одному на каждую группу)
        p_block: P-блок для перемешивания
        rounds: количество раундов
        """
        self.s_blocks = s_blocks
        self.p_block = p_block
        self.rounds = rounds
        
        # Проверяем, что суммарный размер входов S-блоков совпадает с P-блоком
        total_input_bits = sum(s.input_bits for s in s_blocks)
        if total_input_bits != p_block.size:
            raise ValueError(f"Сумма входов S-блоков ({total_input_bits}) не равна размеру P-блока ({p_block.size})")
    
    def split_into_groups(self, bits):
        """Разбивает биты на группы согласно входным размерам S-блоков"""
        groups = []
        idx = 0
        for s in self.s_blocks:
            group_size = s.input_bits
            groups.append(bits[idx:idx + group_size])
            idx += group_size
        return groups
    
    def combine_groups(self, groups):
        """Объединяет группы битов в один список"""
        result = []
        for group in groups:
            result.extend(group)
        return result
    
    def process_s_blocks(self, groups):
        """Пропускает каждую группу через соответствующий S-блок"""
        new_groups = []
        for s_block, group in zip(self.s_blocks, groups):
            new_groups.append(s_block.substitute_bits(group))
        return new_groups
    
    def encrypt_block(self, bits):
        """
        Шифрует один блок битов (длина должна совпадать с размером P-блока)
        """
        if len(bits) != self.p_block.size:
            raise ValueError(f"Размер блока {len(bits)} не равен {self.p_block.size}")
        
        current = bits.copy()
        
        for round_num in range(self.rounds):
            # 1. Разбиваем на группы
            groups = self.split_into_groups(current)
            
            # 2. Применяем S-блоки
            substituted_groups = self.process_s_blocks(groups)
            
            # 3. Объединяем
            combined = self.combine_groups(substituted_groups)
            
            # 4. Применяем P-блок (перестановку)
            current = self.p_block.permute(combined)
        
        return current
    
    def __str__(self):
        return f"Продукционный шифр: {self.rounds} раундов, {len(self.s_blocks)} S-блоков"


# ------------------------------------------------------------
# 4. ПРИМЕР: шифр 12-битных блоков (как на иллюстрации 8.13)
# ------------------------------------------------------------
def create_example_cipher():
    """
    Создаёт пример шифра, аналогичного описанному в тексте:
    - Вход 12 бит
    - 4 S-блока по 3 бита на входе (каждый 3->3)
    - P-блок на 12 бит
    """
    
    # S-блоки: таблица замены из текста (01234567 -> 24506713)
    # Для 3-битных чисел: 0->2, 1->4, 2->5, 3->0, 4->6, 5->7, 6->1, 7->3
    substitution_3bit = {
        0: 2, 1: 4, 2: 5, 3: 0,
        4: 6, 5: 7, 6: 1, 7: 3
    }
    
    # Создаём 4 одинаковых S-блока (в реальном шифре они могут быть разными)
    s_blocks = [
        SBlock(substitution_3bit, input_bits = 3, output_bits = 3),
        SBlock(substitution_3bit, input_bits = 3, output_bits = 3),
        SBlock(substitution_3bit, input_bits = 3, output_bits = 3),
        SBlock(substitution_3bit, input_bits = 3, output_bits = 3),
    ]
    
    # P-блок: перестановка как в тексте (01234567 -> 36071245)
    # Для 12 бит: создадим разумную перестановку
    # Индексы 0..11, перемешиваем их
    permutation_12 = [3, 6, 0, 7, 1, 2, 4, 5, 8, 11, 9, 10]
    p_block = PBlock(permutation_12)
    
    return ProductCipher(s_blocks, p_block, rounds = 4)


# ------------------------------------------------------------
# 5. ДЕМОНСТРАЦИЯ
# ------------------------------------------------------------
def bits_to_str(bits):
    """Преобразует список битов в читаемую строку"""
    return ''.join(str(b) for b in bits)

def str_to_bits(s):
    """Преобразует строку из '0' и '1' в список битов"""
    return [int(c) for c in s if c in '01']

def demo():
    print("=" * 60)
    print("ДЕМОНСТРАЦИЯ КРИПТОГРАФИЧЕСКИХ ПРИНЦИПОВ")
    print("На основе текста о P-блоках, S-блоках и продукционных шифрах")
    print("=" * 60)
    
    # 1. Демонстрация P-блока
    print("\n1. P-БЛОК (перестановка битов):")
    print("   Принцип: биты меняются местами без вычислений")
    p_small = PBlock([3, 6, 0, 7, 1, 2, 4, 5])  # 8-битная перестановка из текста
    test_bits = [0, 1, 2, 3, 4, 5, 6, 7]  # для наглядности используем числа как метки
    print(f"   Вход:  {test_bits}")
    print(f"   Выход: {p_small.permute(test_bits)}")
    
    # 2. Демонстрация S-блока
    print("\n2. S-БЛОК (подстановка):")
    print("   Принцип: замена входного значения по таблице")
    s_example = SBlock({0: 2, 1: 4, 2: 5, 3: 0, 4: 6, 5: 7, 6: 1, 7: 3}, 3, 3)
    for i in range(8):
        bits_in = [(i >> 2) & 1, (i >> 1) & 1, i & 1]
        bits_out = s_example.substitute_bits(bits_in)
        print(f"   {i:03b} ({i}) -> {bits_out} ({s_example.substitute(i)})")
    
    # 3. Демонстрация продукционного шифра
    print("\n3. ПРОДУКЦИОННЫЙ ШИФР:")
    print("   Каскадное применение S-блоков и P-блоков в несколько раундов")
    
    cipher = create_example_cipher()
    print(f"   {cipher}")
    print(f"   {cipher.s_blocks[0]}")
    print(f"   {cipher.p_block}")
    
    # Шифруем тестовое сообщение
    test_message = "101011001010"  # 12 бит
    test_bits = str_to_bits(test_message)
    
    print(f"\n   Исходное сообщение: {test_message}")
    
    encrypted = cipher.encrypt_block(test_bits)
    print(f"   Зашифрованное:      {bits_to_str(encrypted)}")
    
    # 4. Демонстрация лавинного эффекта (малое изменение входа -> большое изменение выхода)
    print("\n4. ЛАВИННЫЙ ЭФФЕКТ:")
    print("   Изменение одного бита на входе сильно меняет выход")
    
    test2_bits = test_bits.copy()
    test2_bits[5] = 1 - test2_bits[5]  # меняем один бит
    
    encrypted2 = cipher.encrypt_block(test2_bits)
    
    # Считаем количество отличающихся битов
    diff = sum(e1 != e2 for e1, e2 in zip(encrypted, encrypted2))
    print(f"   Оригинал:           {bits_to_str(test_bits)}")
    print(f"   С изменённым битом: {bits_to_str(test2_bits)} (изменён бит 5)")
    print(f"   Шифротекст 1:       {bits_to_str(encrypted)}")
    print(f"   Шифротекст 2:       {bits_to_str(encrypted2)}")
    print(f"   Отличается {diff} из {len(encrypted)} бит ({diff / len(encrypted) * 100:.0f}%)")
    
    # 5. Соответствие принципу Керкгоффса
    print("\n5. ПРИНЦИП КЕРКГОФФСА:")
    print("   'Взломщик знает, что используется метод перестановки и подстановки,")
    print("    но он не знает, в каком порядке эти биты располагаются.'")
    print("   В нашей программе алгоритм (P-блоки и S-блоки) известен,")
    print("   но без ключа (таблиц подстановки и перестановки) расшифровать нельзя.")
    
    print("\n" + "=" * 60)
    print("Программа демонстрирует принципы из текста:")
    print("- P-блок: перестановка битов (аппаратно - со скоростью света)")
    print("- S-блок: подстановка через таблицы")
    print("- Продукционный шифр: каскад раундов")
    print("- Лавинный эффект: сложная зависимость выхода от входа")
    print("=" * 60)


# ------------------------------------------------------------
# 6. ДОПОЛНИТЕЛЬНО: расшифровка (для симметричного шифра)
# ------------------------------------------------------------
class DecryptableProductCipher(ProductCipher):
    """
    Расширяемый продукционный шифр с возможностью расшифровки.
    Для расшифровки нужны обратные S-блоки и обратная перестановка.
    """
    
    def __init__(self, s_blocks, p_block, inv_s_blocks, inv_p_block, rounds = 4):
        """
        inv_s_blocks: обратные S-блоки
        inv_p_block: обратный P-блок
        """
        super().__init__(s_blocks, p_block, rounds)
        self.inv_s_blocks = inv_s_blocks
        self.inv_p_block = inv_p_block
    
    def decrypt_block(self, bits):
        """Расшифровывает блок (обратный порядок операций)"""
        if len(bits) != self.p_block.size:
            raise ValueError(f"Размер блока {len(bits)} не равен {self.p_block.size}")
        
        current = bits.copy()
        
        for round_num in range(self.rounds):
            # 1. Обратная перестановка
            current = self.inv_p_block.permute(current)
            
            # 2. Разбиваем на группы
            groups = self.split_into_groups(current)
            
            # 3. Обратные S-блоки
            new_groups = []
            for inv_s, group in zip(self.inv_s_blocks, groups):
                new_groups.append(inv_s.substitute_bits(group))
            
            # 4. Объединяем
            current = self.combine_groups(new_groups)
        
        return current


def create_full_cipher():
    """Создаёт шифр с возможностью расшифровки"""
    # Прямая таблица подстановки
    s_table = {0: 2, 1: 4, 2: 5, 3: 0, 4: 6, 5: 7, 6: 1, 7: 3}
    # Обратная таблица
    inv_s_table = {v: k for k, v in s_table.items()}
    
    s_blocks = [SBlock(s_table, 3, 3) for _ in range(4)]
    inv_s_blocks = [SBlock(inv_s_table, 3, 3) for _ in range(4)]
    
    perm = [3, 6, 0, 7, 1, 2, 4, 5, 8, 11, 9, 10]
    # Обратная перестановка: inv_perm[new_pos] = old_pos
    inv_perm = [0] * len(perm)
    for i, p in enumerate(perm):
        inv_perm[p] = i
    
    p_block = PBlock(perm)
    inv_p_block = PBlock(inv_perm)
    
    return DecryptableProductCipher(s_blocks, p_block, inv_s_blocks, inv_p_block, rounds = 4)


def demo_full():
    """Полная демонстрация шифрования и расшифровки"""
    print("\n" + "=" * 60)
    print("ПОЛНАЯ ДЕМОНСТРАЦИЯ: ШИФРОВАНИЕ И РАСШИФРОВКА")
    print("=" * 60)
    
    cipher = create_full_cipher()
    
    # Исходное сообщение
    plaintext = "101011001010"
    print(f"\nИсходный текст: {plaintext}")
    
    # Шифрование
    plain_bits = str_to_bits(plaintext)
    encrypted = cipher.encrypt_block(plain_bits)
    print(f"Зашифровано:    {bits_to_str(encrypted)}")
    
    # Расшифровка
    decrypted = cipher.decrypt_block(encrypted)
    print(f"Расшифровано:   {bits_to_str(decrypted)}")
    
    # Проверка
    if plain_bits == decrypted:
        print("\n✓ УСПЕХ! Расшифрованный текст совпадает с исходным.")
    else:
        print("\n✗ ОШИБКА: Расшифрованный текст не совпадает.")


# ------------------------------------------------------------
# ЗАПУСК
# ------------------------------------------------------------
if __name__ == "__main__":
    demo()
    demo_full()