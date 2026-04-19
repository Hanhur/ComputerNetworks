import random
import secrets

# ------------------------------------------------------------
# 1. Вспомогательные функции
# ------------------------------------------------------------

def random_bit() -> int:
    """Случайный бит (0 или 1)"""
    return secrets.randbits(1)

def random_basis() -> str:
    """Случайный базис: '+' (прямолинейный) или 'x' (диагональный)"""
    return '+' if secrets.randbits(1) == 0 else 'x'

def encode_bit(bit: int, basis: str) -> str:
    """
    Кодирует бит в поляризацию фотона.
    По условию:
    - Для прямолинейного базиса (+): 0 = вертикаль (|), 1 = горизонталь (-)
    - Для диагонального базиса (x):   0 = 45° (/), 1 = 135° (\)
    """
    if basis == '+':
        return '|' if bit == 0 else '-'
    else:  # диагональный
        return '/' if bit == 0 else '\\'

def measure_photon(photon: str, basis: str) -> int:
    """
    Измерение фотона в заданном базисе.
    Если базис совпадает с базисом кодирования -> результат определён.
    Если не совпадает -> случайный бит (0 или 1) с равной вероятностью.
    """
    # Правильные соответствия
    correct_map = {
        ('+', '|'): 0, ('+', '-'): 1,
        ('x', '/'): 0, ('x', '\\'): 1
    }
    key = (basis, photon)
    if key in correct_map:
        return correct_map[key]
    else:
        # Неправильный базис — квантовая случайность
        return random_bit()

# ------------------------------------------------------------
# 2. Основная симуляция BB84
# ------------------------------------------------------------

def run_bb84(num_bits: int, eavesdrop: bool = False) -> dict:
    """
    Запускает протокол BB84.
    Если eavesdrop = True, Труди перехватывает фотоны (измеряет в случайном базисе
    и пересылает то, что измерила).
    Возвращает словарь со статистикой и итоговыми ключами.
    """
    # Алиса: исходный ключ и базисы
    alice_bits = [random_bit() for _ in range(num_bits)]
    alice_bases = [random_basis() for _ in range(num_bits)]
    
    # Кодирование фотонов
    photons = [encode_bit(alice_bits[i], alice_bases[i]) for i in range(num_bits)]
    
    # --- Канал передачи (с возможным прослушиванием) ---
    if eavesdrop:
        # Труди выбирает случайный базис для каждого фотона и измеряет его
        eve_bases = [random_basis() for _ in range(num_bits)]
        eve_measured_bits = [measure_photon(photons[i], eve_bases[i]) for i in range(num_bits)]
        # Труди пересылает Бобу переизлученные фотоны (согласно её измерению)
        # В реальности она не знает бит, только поляризацию. Моделируем:
        forwarded_photons = [encode_bit(eve_measured_bits[i], eve_bases[i]) for i in range(num_bits)]
        received_photons = forwarded_photons
        eve_info = {
            'bases': eve_bases,
            'measured_bits': eve_measured_bits
        }
    else:
        received_photons = photons.copy()
        eve_info = None
    
    # Боб: случайный выбор базисов для измерения
    bob_bases = [random_basis() for _ in range(num_bits)]
    bob_raw_bits = [measure_photon(received_photons[i], bob_bases[i]) for i in range(num_bits)]
    
    # --------------------------------------------------------
    # 3. Открытый канал: согласование базисов
    # --------------------------------------------------------
    matching_indices = []
    for i in range(num_bits):
        if alice_bases[i] == bob_bases[i]:
            matching_indices.append(i)
    
    # Отфильтрованный ключ (только совпавшие позиции)
    sifted_key_alice = [alice_bits[i] for i in matching_indices]
    sifted_key_bob   = [bob_raw_bits[i] for i in matching_indices]
    
    # Оценка ошибок (если есть прослушивание, ошибки возрастут)
    errors = sum(1 for a, b in zip(sifted_key_alice, sifted_key_bob) if a != b)
    qber = errors / len(sifted_key_alice) if sifted_key_alice else 0
    
    # --------------------------------------------------------
    # 4. (Опционально) Усиление секретности — упрощённо:
    #    Берём только первую половину совпавших битов как финальный ключ
    # --------------------------------------------------------
    final_key_length = len(sifted_key_alice) // 2
    final_key_alice = sifted_key_alice[:final_key_length]
    final_key_bob   = sifted_key_bob[:final_key_length]
    
    return {
        'num_bits': num_bits,
        'eavesdrop': eavesdrop,
        'alice_bases': alice_bases,
        'bob_bases': bob_bases,
        'matching_indices': matching_indices,
        'sifted_key_length': len(sifted_key_alice),
        'errors_in_sifted': errors,
        'qber': qber,
        'final_key_alice': final_key_alice,
        'final_key_bob': final_key_bob,
        'key_match': final_key_alice == final_key_bob,
        'eve_info': eve_info
    }

# ------------------------------------------------------------
# 5. Пример использования и красивый вывод
# ------------------------------------------------------------

def print_results(res: dict):
    print("="*60)
    print(f"Количество переданных кубитов: {res['num_bits']}")
    print(f"Прослушивание Труди: {'ДА' if res['eavesdrop'] else 'НЕТ'}")
    print(f"Совпало базисов: {len(res['matching_indices'])} из {res['num_bits']}")
    print(f"Длина просеянного ключа: {res['sifted_key_length']}")
    print(f"Ошибок в просеянном ключе: {res['errors_in_sifted']}")
    print(f"QBER (коэф. ошибок): {res['qber']:.2%}")
    print(f"Финальный ключ (Алиса): {''.join(map(str, res['final_key_alice']))}")
    print(f"Финальный ключ (Боб):   {''.join(map(str, res['final_key_bob']))}")
    print(f"Ключи совпадают: {'ДА' if res['key_match'] else 'НЕТ'}")
    
    if res['eavesdrop'] and res['eve_info']:
        eve_correct_guesses = sum(1 for i in res['matching_indices'] if i < len(res['eve_info']['bases']) and res['eve_info']['bases'][i] == res['alice_bases'][i])
        print(f"Из {len(res['matching_indices'])} совпавших позиций Труди угадала базис в {eve_correct_guesses} случаях")
    
    print("="*60)

# ------------------------------------------------------------
# Запуск симуляции
# ------------------------------------------------------------
if __name__ == "__main__":
    # Случай 1: без прослушивания
    result_clean = run_bb84(num_bits=100, eavesdrop=False)
    print_results(result_clean)
    
    print("\n")
    
    # Случай 2: с прослушиванием Труди
    result_eve = run_bb84(num_bits=100, eavesdrop=True)
    print_results(result_eve)