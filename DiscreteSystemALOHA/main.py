import random
import math

def simulate_slotted_aloha(num_stations, G, num_slots):
    """
    Моделирование слотовой ALOHA.
    
    Параметры:
        num_stations : int - количество станций
        G : float - среднее число попыток передачи за слот (нагрузка)
        num_slots : int - количество слотов для моделирования
    
    Возвращает:
        stats : dict - статистика по моделированию
    """
    # Вероятность передачи для каждой станции в каждом слоте
    p = G / num_stations
    
    # Массивы для статистики
    empty_slots = 0
    success_slots = 0
    collision_slots = 0
    
    for _ in range(num_slots):
        # Каждая станция решает, передавать ли в этом слоте
        transmissions = 0
        for _ in range(num_stations):
            if random.random() < p:
                transmissions += 1
        
        if transmissions == 0:
            empty_slots += 1
        elif transmissions == 1:
            success_slots += 1
        else:
            collision_slots += 1
    
    return {
        'empty': empty_slots / num_slots,
        'success': success_slots / num_slots,
        'collision': collision_slots / num_slots,
        'throughput': success_slots / num_slots  # S
    }


def theoretical_throughput(G):
    """Теоретическая пропускная способность слотовой ALOHA: S = G * e^(-G)"""
    return G * math.exp(-G)


def analyze_performance_at_optimal():
    """Анализ работы системы при оптимальной нагрузке G = 1"""
    G_opt = 1.0
    num_stations = 50
    num_slots = 50000
    
    stats = simulate_slotted_aloha(num_stations, G_opt, num_slots)
    
    print("=" * 70)
    print(f"Анализ слотовой ALOHA при оптимальной нагрузке G = {G_opt}")
    print("=" * 70)
    print(f"Теоретическая пропускная способность: {theoretical_throughput(G_opt):.4f}")
    print(f"\nРезультаты моделирования ({num_slots} слотов, {num_stations} станций):")
    print(f"  Пустые слоты:     {stats['empty'] * 100:.1f}% (теория: 36.8%)")
    print(f"  Успешные передачи: {stats['success'] * 100:.1f}% (теория: 36.8%)")
    print(f"  Коллизии:          {stats['collision'] * 100:.1f}% (теория: 26.4%)")
    print(f"\nОжидаемое число попыток для одного кадра: E = e^G = {math.exp(G_opt):.2f}")
    print(f"\nПодтверждение из текста: '37 % интервалов будут пустыми, 37 % - с успешно переданными фреймами и 26 % - с коллизией'")


def show_unstable_behavior():
    """Демонстрация экспоненциального роста числа попыток при увеличении G"""
    G_values = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]
    print("\n" + "=" * 70)
    print("Влияние нагрузки G на среднее число попыток передачи E = e^G")
    print("=" * 70)
    print(" G | E = e^G | Пропускная способность S | Эффективность")
    print("-" * 70)
    for G in G_values:
        E = math.exp(G)
        S = theoretical_throughput(G)
        print(f" {G:.1f} | {E:7.2f} | {S:.4f} | {S / G * 100:.1f} %")
    print("\n" + "-" * 70)
    print("Вывод: даже небольшой рост G резко увеличивает число коллизий и повторных попыток.")
    print("При G=3 требуется в среднем 20 попыток для успешной передачи кадра!")


def compare_with_pure_aloha():
    """Сравнение с чистой ALOHA"""
    print("\n" + "=" * 70)
    print("Сравнение с чистой ALOHA")
    print("=" * 70)
    
    G_opt = 1.0
    S_slotted = theoretical_throughput(G_opt)
    S_pure = 0.5 * theoretical_throughput(G_opt)  # Чистая ALOHA: S = G*e^(-2G) при G=0.5
    
    print(f"Слотовая ALOHA (Roberts, 1972):")
    print(f"  - Уязвимый интервал: T (один слот)")
    print(f"  - Максимальная пропускная способность: S = 1/e ≈ {1 / math.e:.4f} (при G=1)")
    print(f"\nЧистая ALOHA (Abramson, 1970):")
    print(f"  - Уязвимый интервал: 2T")
    print(f"  - Максимальная пропускная способность: S = 1/(2e) ≈ {1 / (2 * math.e):.4f} (при G=0.5)")
    print(f"\n➜ Увеличение производительности: в 2 раза!")
    print(f"   {S_slotted:.4f} / {S_pure:.4f} = {S_slotted / S_pure:.0f}x")


def table_of_results():
    """Таблица результатов для разных значений G"""
    print("\n" + "=" * 70)
    print("Производительность слотовой ALOHA при различной нагрузке")
    print("=" * 70)
    print(" G | S(G)=G·e⁻ᴳ | Пустые слоты | Успешно | Коллизии")
    print("-" * 70)
    
    test_G = [0.2, 0.5, 0.8, 1.0, 1.2, 1.5, 2.0, 3.0]
    
    for G in test_G:
        S = theoretical_throughput(G)
        empty = math.exp(-G)  # P(0 передач)
        success = G * math.exp(-G)  # S = G·e⁻ᴳ
        collision = 1 - empty - success
        
        print(f" {G:.1f} | {S:.4f} | {empty * 100:.1f} % | {success * 100:.1f} % | {collision * 100:.1f} %")
    
    print("\n" + "-" * 70)
    print("При G = 1: 37% пустых, 37% успешных, 26% коллизий — оптимальный режим")
    print("При G > 2: система перегружена, коллизий больше 40%")


def calculate_expected_attempts():
    """Расчёт ожидаемого числа попыток"""
    print("\n" + "=" * 70)
    print("Ожидаемое число попыток передачи для одного кадра")
    print("=" * 70)
    print("Из текста: E = e^G")
    print("\n G | E = e^G | Пояснение")
    print("-" * 40)
    
    for G in [0.5, 1.0, 1.5, 2.0, 2.5, 3.0]:
        E = math.exp(G)
        bar = "█" * min(int(E), 30)
        print(f" {G:.1f} | {E:.1f} {bar}")
    
    print("\n" + "-" * 40)
    print("Экспоненциальная зависимость: небольшое увеличение G")
    print("приводит к резкому росту числа коллизий и повторных передач.")


# ===================== ЗАПУСК ПРОГРАММЫ =====================
if __name__ == "__main__":
    print("\n" + "█" * 70)
    print("ДИСКРЕТНАЯ (СЛОТОВАЯ) СИСТЕМА ALOHA")
    print("Моделирование на основе работы Roberts (1972)")
    print("█" * 70)
    
    # 1. Анализ при оптимальной нагрузке G=1
    analyze_performance_at_optimal()
    
    # 2. Сравнение с чистой ALOHA
    compare_with_pure_aloha()
    
    # 3. Демонстрация нестабильности
    show_unstable_behavior()
    
    # 4. Таблица результатов
    table_of_results()
    
    # 5. Расчёт ожидаемого числа попыток
    calculate_expected_attempts()
    
    # 6. Дополнительный эксперимент: влияние количества станций
    print("\n" + "=" * 70)
    print("Эксперимент: влияние количества станций при фиксированной нагрузке G = 1")
    print("=" * 70)
    
    G_fixed = 1.0
    num_slots = 20000
    
    for stations in [10, 50, 100, 200]:
        stats = simulate_slotted_aloha(stations, G_fixed, num_slots)
        print(f"  Станций: {stations:3d} → Успешных передач: {stats['success'] * 100:.1f} %")
    
    print("\n" + "=" * 70)
    print("ВЫВОД (из текста):")
    print("  • Слотовая ALOHA удваивает производительность чистой ALOHA")
    print("  • Уязвимый интервал сокращается с 2T до T")
    print("  • При G = 1: 37% пустых, 37% успешных, 26% коллизий")
    print("  • E = e^G — экспоненциальный рост числа попыток")
    print("  • Протокол был переоткрыт для кабельного интернета (DOCSIS)")
    print("=" * 70)