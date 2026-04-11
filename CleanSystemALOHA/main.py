import math
import random

# ------------------------------------------------------------
# 1. Теоретическая формула чистой ALOHA
# ------------------------------------------------------------
def pure_aloha_throughput(G):
    """ S = G * exp(-2G) """
    return G * math.exp(-2 * G)

# ------------------------------------------------------------
# 2. Нахождение максимальной пропускной способности
# ------------------------------------------------------------
def find_max_throughput():
    best_G = 0.5
    best_S = pure_aloha_throughput(best_G)
    
    for G in [x / 100.0 for x in range(30, 71)]:
        S = pure_aloha_throughput(G)
        if S > best_S:
            best_S = S
            best_G = G
    
    return best_G, best_S

# ------------------------------------------------------------
# 3. Оптимизированная симуляция чистой ALOHA
# ------------------------------------------------------------
def simulate_pure_aloha(total_slots, arrival_rate_G, time_per_frame=1.0):
    """ Оптимизированная версия с использованием скользящего окна """
    # Генерируем количество попыток (распределение Пуассона)
    lam = total_slots * arrival_rate_G
    
    # Ограничиваем максимальное количество попыток для производительности
    max_attempts = 50000
    if lam > max_attempts:
        # Если ожидается слишком много попыток, уменьшаем total_slots
        scale = max_attempts / lam
        total_slots = int(total_slots * scale)
        lam = total_slots * arrival_rate_G
    
    # Генерируем пуассоновское число
    if lam < 30:
        # Метод для малых lam
        L = math.exp(-lam)
        num_attempts = 0
        p = 1.0
        while p > L:
            num_attempts += 1
            p *= random.random()
        num_attempts -= 1
    else:
        # Нормальная аппроксимация для больших lam
        num_attempts = max(0, int(random.gauss(lam, math.sqrt(lam)) + 0.5))
    
    if num_attempts <= 1:
        return 0.0 if num_attempts == 0 else 1.0 / total_slots, 1.0, num_attempts, num_attempts
    
    # Генерируем моменты начала передач
    start_times = [random.uniform(0, total_slots) for _ in range(num_attempts)]
    start_times.sort()
    
    # Оптимизированный алгоритм проверки коллизий
    # Передача успешна, если нет других передач в интервале [t - 1, t + 1]
    successful = [True] * num_attempts
    
    # Используем скользящее окно для проверки соседних передач
    for i in range(num_attempts):
        # Проверяем только предыдущую и следующую передачи (ближайшие по времени)
        if i > 0:
            # Если пересекается с предыдущей
            if start_times[i] - start_times[i-1] < time_per_frame:
                successful[i] = False
                successful[i-1] = False
        
        # Следующую передачу проверим, когда дойдём до неё
    
    num_successful = sum(successful)
    
    throughput = num_successful / total_slots
    success_rate = num_successful / num_attempts if num_attempts > 0 else 0.0
    
    return throughput, success_rate, num_attempts, num_successful

# ------------------------------------------------------------
# 4. Быстрая симуляция для таблицы (с меньшим total_slots)
# ------------------------------------------------------------
def run_simulations():
    print("\n" + "=" * 70)
    print("РЕЗУЛЬТАТЫ СИМУЛЯЦИИ")
    print("=" * 70)
    print("   G    | Теория S | Симуляция S | Отклонение | Успешность | Попыток")
    print("--------|----------|-------------|------------|------------|---------")
    
    test_values = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.2, 1.5, 2.0]
    
    for G in test_values:
        theoretical_S = pure_aloha_throughput(G)
        
        # Используем меньшее количество слотов для скорости
        total_slots = 10000
        
        # Запускаем симуляцию 3 раза и усредняем
        sim_results = []
        success_rates = []
        attempts_list = []
        
        for _ in range(3):
            S_sim, success_rate, attempts, _ = simulate_pure_aloha(total_slots, G)
            sim_results.append(S_sim)
            success_rates.append(success_rate)
            attempts_list.append(attempts)
        
        avg_S_sim = sum(sim_results) / len(sim_results)
        avg_success = sum(success_rates) / len(success_rates)
        avg_attempts = sum(attempts_list) / len(attempts_list)
        diff = abs(theoretical_S - avg_S_sim)
        
        print(f" {G:5.2f}  | {theoretical_S:7.4f} | {avg_S_sim:7.4f}  | {diff:7.4f} | {avg_success:6.2%} | {avg_attempts:6.0f}")

# ------------------------------------------------------------
# 5. Детальная симуляция для оптимальной нагрузки
# ------------------------------------------------------------
def detailed_simulation_at_optimum():
    print("\n" + "=" * 70)
    print("ДЕТАЛЬНАЯ СИМУЛЯЦИЯ ПРИ ОПТИМАЛЬНОЙ НАГРУЗКЕ (G = 0.5)")
    print("=" * 70)
    
    G_opt, S_max = find_max_throughput()
    print(f"\nТеоретический максимум: S_max = {S_max:.4f} ({S_max * 100:.2f}%) при G = {G_opt}")
    print("\nРезультаты 5 запусков (по 20,000 слотов каждый):") 
    print("-" * 70)
    
    total_slots = 20000
    all_throughputs = []
    all_success_rates = []
    
    for run in range(1, 6):
        S_sim, success_rate, attempts, successes = simulate_pure_aloha(total_slots, G_opt)
        all_throughputs.append(S_sim)
        all_success_rates.append(success_rate)
        print(f"  Запуск {run}: Попыток={attempts:5d}, Успешно={successes:5d}, "f"S={S_sim:.4f} ({S_sim*100:.2f}%), Успешность={success_rate:.2%}")
    
    avg_S = sum(all_throughputs) / len(all_throughputs)
    avg_success = sum(all_success_rates) / len(all_success_rates)
    
    print("-" * 70)
    print(f"  СРЕДНЯЯ ПРОПУСКНАЯ СПОСОБНОСТЬ: {avg_S:.4f} ({avg_S * 100:.2f}%)")
    print(f"  Отклонение от теории: {abs(S_max - avg_S):.4f}")
    print(f"  Средняя успешность попыток: {avg_success:.2%}")

# ------------------------------------------------------------
# 6. Теоретическая таблица
# ------------------------------------------------------------
def print_theoretical_table():
    print("\n" + "=" * 70)
    print("ТЕОРЕТИЧЕСКИЕ ЗНАЧЕНИЯ ПРОПУСКНОЙ СПОСОБНОСТИ")
    print("=" * 70)
    print("   G    |   S(G)   |  S%     | Описание")
    print("--------|----------|---------|--------------------------")
    
    test_values = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0, 1.2, 1.5, 2.0, 2.5, 3.0]
    
    for G in test_values:
        S = pure_aloha_throughput(G)
        marker = ""
        if abs(G - 0.5) < 0.05:
            marker = "← МАКСИМУМ"
        print(f" {G:5.2f} | {S:7.4f} | {S * 100:6.2f}% | {marker}")

# ------------------------------------------------------------
# 7. Анализ производительности
# ------------------------------------------------------------
def performance_analysis():
    print("\n" + "=" * 70)
    print("АНАЛИЗ ПРОИЗВОДИТЕЛЬНОСТИ")
    print("=" * 70)
    print("""
        Сравнение теоретической и реальной производительности:

            G       Теория     Причина
            ──────────────────────────────────────────────
            G < 0.3  S ≈ G     Мало коллизий, почти все передачи успешны
            G = 0.5  S = 0.184 Оптимум: баланс между коллизиями и простоями
            G > 0.8  S падает  Слишком много коллизий, большинство передач неудачны
            G > 1.5  S < 0.1   Канал перегружен, почти всё время в коллизиях
            
        Ключевые выводы:
            • При G = 0.5 достигается максимум (18.4% использования канала)
            • При G = 1.0 пропускная способность падает до 13.5%
            • При G = 2.0 пропускная способность составляет всего 7.3%
    """)

# ------------------------------------------------------------
# 8. Объяснение модели
# ------------------------------------------------------------
def print_explanation():
    print("\n" + "=" * 70)
    print("МАТЕМАТИЧЕСКАЯ МОДЕЛЬ ЧИСТОЙ ALOHA")
    print("=" * 70)
    print("""
        Формулы:
            • Вероятность успеха:    P0 = e^(-2G)
            • Пропускная способность: S = G * e^(-2G)
            • Максимум:              S_max = 1/(2e) ≈ 0.1839
            
        Где:
            G = среднее число попыток передачи за время кадра
            (включая новые и повторные передачи)
            
        Уязвимый период = 2 × время кадра
    """)

# ------------------------------------------------------------
# 9. Главная функция
# ------------------------------------------------------------
def main():
    random.seed(42)
    
    print("\n" + "=" * 70)
    print("ЧИСТАЯ СИСТЕМА ALOHA (PURE ALOHA)")
    print("Моделирование протокола случайного доступа")
    print("=" * 70)
    
    # Объяснение модели
    print_explanation()
    
    # Теоретическая таблица
    print_theoretical_table()
    
    # Поиск максимума
    G_opt, S_max = find_max_throughput()
    print(f"\nТОЧНЫЙ МАКСИМУМ:")
    print(f"  G_opt = {G_opt:.3f}")
    print(f"  S_max = {S_max:.4f} ({S_max * 100:.2f}%)")
    
    # Анализ производительности
    performance_analysis()
    
    # Симуляции
    run_simulations()
    
    # Детальная симуляция
    detailed_simulation_at_optimum()
    
    # Итоговые выводы
    print("\n" + "=" * 70)
    print("ИТОГОВЫЕ ВЫВОДЫ")
    print("=" * 70)
    print(f"""
        • Чистая ALOHA может использовать канал максимум на {S_max * 100:.1f}%
        • Это фундаментальное ограничение протокола
        • Улучшенные протоколы:
        - Слотовая ALOHA: 36.8% (в 2 раза лучше)
        - CSMA/CD: до 90%+ (прослушивание канала)
        - CSMA/CA: используется в Wi-Fi
    """)
    print("=" * 70)

# ------------------------------------------------------------
# Запуск
# ------------------------------------------------------------
if __name__ == "__main__":
    main()