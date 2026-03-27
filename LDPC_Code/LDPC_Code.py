import random

def demonstrate_ldpc_concepts_simple():
    """
    Упрощенная демонстрация основных концепций LDPC-кодов
    """
    
    print("=" * 60)
    print("ДЕМОНСТРАЦИЯ КОНЦЕПЦИЙ LDPC-КОДОВ")
    print("=" * 60)
    
    # 1. СОЗДАНИЕ РАЗРЕЖЕННОЙ ПРОВЕРОЧНОЙ МАТРИЦЫ
    print("\n1. СОЗДАНИЕ РАЗРЕЖЕННОЙ ПРОВЕРОЧНОЙ МАТРИЦЫ H")
    print("-" * 40)
    
    # Параметры кода
    n = 8  # длина кодового слова
    m = 4  # количество проверочных уравнений
    
    # Создаем разреженную матрицу вручную
    print("Создаем разреженную матрицу с низкой плотностью единиц:")
    H = []
    for i in range(m):
        row = [0] * n
        # Добавляем 2-3 единицы в каждой строке (низкая плотность)
        positions = random.sample(range(n), random.randint(2, 3))
        for pos in positions:
            row[pos] = 1
        H.append(row)
        print(f"Строка {i+1}: {row}")
    
    print("\nЭто разреженная матрица - низкая плотность единиц!")
    
    # 2. ФОРМИРОВАНИЕ КОДОВОГО СЛОВА
    print("\n2. ФОРМИРОВАНИЕ КОДОВОГО СЛОВА")
    print("-" * 40)
    print("Каждый выходной бит формируется из подмножества входных битов")
    
    # Исходное сообщение
    k = n - m  # количество информационных битов
    message = [random.randint(0, 1) for _ in range(k)]
    print(f"Исходное сообщение (k={k} бит): {message}")
    
    # Создаем кодовое слово
    code_word = message.copy()
    # Добавляем проверочные биты (упрощенно)
    for _ in range(m):
        code_word.append(0)
    
    print(f"Кодовое слово (n={n} бит): {code_word}")
    
    # 3. ПРОВЕРКА УСЛОВИЙ ЧЕТНОСТИ
    print("\n3. ПРОВЕРКА УСЛОВИЙ ЧЕТНОСТИ")
    print("-" * 40)
    
    print("Проверка условий четности (должны быть все 0):")
    all_parities_ok = True
    for i in range(m):
        parity = 0
        for j in range(n):
            if H[i][j] == 1:
                parity ^= code_word[j]
        print(f"Уравнение {i+1}: {parity}")
        if parity != 0:
            all_parities_ok = False
    
    if all_parities_ok:
        print("✓ Все условия четности выполнены!")
    
    # 4. МОДЕЛИРОВАНИЕ ОШИБОК
    print("\n4. МОДЕЛИРОВАНИЕ ОШИБОК ПРИ ПЕРЕДАЧЕ")
    print("-" * 40)
    
    # Вносим ошибку
    received = code_word.copy()
    error_pos = random.randint(0, n-1)
    received[error_pos] ^= 1  # инвертируем бит
    
    print(f"Переданное слово:    {code_word}")
    print(f"Ошибка в позиции:    {error_pos + 1}")
    print(f"Принятое с ошибкой:  {received}")
    
    # 5. ОБНАРУЖЕНИЕ ОШИБОК
    print("\n5. ОБНАРУЖЕНИЕ ОШИБОК")
    print("-" * 40)
    
    print("Проверяем условия четности для принятого слова:")
    error_detected = False
    for i in range(m):
        parity = 0
        for j in range(n):
            if H[i][j] == 1:
                parity ^= received[j]
        if parity != 0:
            error_detected = True
            print(f"Уравнение {i+1}: {parity} ❌ Нарушение!")
        else:
            print(f"Уравнение {i+1}: {parity} ✓ OK")
    
    if error_detected:
        print("\n✓ Ошибка успешно обнаружена!")
    
    # 6. ПРЕИМУЩЕСТВА LDPC
    print("\n6. ПРЕИМУЩЕСТВА LDPC-КОДОВ")
    print("-" * 40)
    print("✓ Превосходно справляются с ошибками - лучше многих других кодов")
    print("✓ Удобно применять для блоков большого размера")
    print("✓ Используются в современных протоколах:")
    print("  • Цифровое телевидение")
    print("  • Ethernet 10 Гбит/с")
    print("  • ЛЭП (Линии электропередач)")
    print("  • Wi-Fi 802.11 (последние версии)")
    print("  • Перспективные разрабатываемые сети")
    print("=" * 60)

if __name__ == "__main__":
    demonstrate_ldpc_concepts_simple()