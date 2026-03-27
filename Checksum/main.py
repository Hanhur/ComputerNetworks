"""
Универсальная программа для обнаружения ошибок в передаче данных
Реализует: IP-контрольную сумму, контрольную сумму Флетчера и CRC
"""

import sys
import os

# ==================== IP КОНТРОЛЬНАЯ СУММА ====================

def calculate_ip_checksum(data):
    """Вычисляет 16-битную контрольную сумму в стиле IP (обратный код)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Разбиваем данные на 16-битные слова
    words = []
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) | data[i + 1]
        else:
            word = (data[i] << 8) | 0
        words.append(word)
    
    # Суммируем все слова с переносом
    checksum = 0
    for word in words:
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    
    return (~checksum) & 0xFFFF


def verify_ip_checksum(data_with_checksum):
    """Проверяет контрольную сумму IP"""
    if len(data_with_checksum) < 2:
        return False
    
    checksum_received = (data_with_checksum[-2] << 8) | data_with_checksum[-1]
    data = data_with_checksum[:-2]
    
    checksum_calculated = calculate_ip_checksum(data)
    
    total = (checksum_calculated + checksum_received) & 0xFFFF
    total = (total & 0xFFFF) + (total >> 16)
    
    return total == 0xFFFF


# ==================== КОНТРОЛЬНАЯ СУММА ФЛЕТЧЕРА ====================

def fletcher_16(data):
    """Вычисляет 16-битную контрольную сумму Флетчера"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    sum1 = 0
    sum2 = 0
    
    for byte in data:
        sum1 = (sum1 + byte) % 255
        sum2 = (sum2 + sum1) % 255
    
    return (sum2 << 8) | sum1


def fletcher_32(data):
    """Вычисляет 32-битную контрольную сумму Флетчера"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    sum1 = 0
    sum2 = 0
    
    for byte in data:
        sum1 = (sum1 + byte) % 65535
        sum2 = (sum2 + sum1) % 65535
    
    return (sum2 << 16) | sum1


def verify_fletcher(data_with_checksum, is_32bit=False):
    """Проверяет контрольную сумму Флетчера"""
    if is_32bit:
        if len(data_with_checksum) < 4:
            return False
        checksum_received = int.from_bytes(data_with_checksum[-4:], 'big')
        data = data_with_checksum[:-4]
        checksum_calculated = fletcher_32(data)
    else:
        if len(data_with_checksum) < 2:
            return False
        checksum_received = int.from_bytes(data_with_checksum[-2:], 'big')
        data = data_with_checksum[:-2]
        checksum_calculated = fletcher_16(data)
    
    return checksum_calculated == checksum_received


# ==================== CRC ====================

class CRC:
    """Реализация CRC (Cyclic Redundancy Check)"""
    
    CRC_8 = 0x07
    CRC_16 = 0x8005
    CRC_32_IEEE = 0xEDB88320
    
    def __init__(self, polynomial=CRC_32_IEEE, initial_value=0xFFFFFFFF, final_xor=0xFFFFFFFF):
        self.polynomial = polynomial
        self.initial_value = initial_value
        self.final_xor = final_xor
        self._crc_table = None
        
        if polynomial == self.CRC_8:
            self.width = 8
        elif polynomial == self.CRC_16:
            self.width = 16
        else:
            self.width = 32
            
        self._build_table()
    
    def _build_table(self):
        """Создает таблицу для быстрого вычисления CRC"""
        self._crc_table = []
        for i in range(256):
            crc = i << (self.width - 8) if self.width > 8 else i
            for _ in range(8):
                if crc & (1 << (self.width - 1)) if self.width > 8 else crc & 0x80:
                    crc = (crc << 1) ^ self.polynomial
                else:
                    crc = crc << 1
                if self.width <= 32:
                    crc &= (1 << self.width) - 1
            self._crc_table.append(crc)
    
    def calculate(self, data):
        """Вычисляет CRC для данных"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        crc = self.initial_value
        
        for byte in data:
            if self.width > 8:
                idx = ((crc >> (self.width - 8)) ^ byte) & 0xFF
                crc = ((crc << 8) ^ self._crc_table[idx]) & ((1 << self.width) - 1)
            else:
                idx = (crc ^ byte) & 0xFF
                crc = (self._crc_table[idx] ^ (crc << 8)) & ((1 << self.width) - 1)
        
        return crc ^ self.final_xor
    
    def verify(self, data_with_crc):
        """Проверяет данные с CRC"""
        crc_bytes = self.width // 8
        
        if len(data_with_crc) < crc_bytes:
            return False
        
        data = data_with_crc[:-crc_bytes]
        crc_received = int.from_bytes(data_with_crc[-crc_bytes:], 'big')
        crc_calculated = self.calculate(data)
        
        return crc_calculated == crc_received
    
    def add_crc(self, data):
        """Добавляет CRC к данным"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        crc_value = self.calculate(data)
        crc_bytes = crc_value.to_bytes(self.width // 8, 'big')
        
        return data + crc_bytes


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def clear_screen():
    """Очищает экран"""
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header(title):
    """Выводит красивый заголовок"""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def print_result(success, message):
    """Выводит результат проверки"""
    if success:
        print(f"  ✅ {message}")
    else:
        print(f"  ❌ {message}")


# ==================== ОСНОВНЫЕ ФУНКЦИИ ====================

def demo_ip_checksum():
    """Демонстрация IP-контрольной суммы"""
    print_header("IP-контрольная сумма (16-бит, обратный код)")
    
    message = input("Введите сообщение (или нажмите Enter для примера): ").strip()
    if not message:
        message = "Hello, World!"
        print(f"Используем пример: {message}")
    
    message_bytes = message.encode('utf-8')
    checksum = calculate_ip_checksum(message_bytes)
    
    print(f"\nИсходное сообщение: {message}")
    print(f"Контрольная сумма: {checksum:04X} (0x{checksum:04X})")
    
    # Формируем кадр
    frame = message_bytes + bytes([(checksum >> 8) & 0xFF, checksum & 0xFF])
    print(f"Кадр для передачи: {frame}")
    
    # Проверяем
    is_valid = verify_ip_checksum(frame)
    print_result(is_valid, "Проверка кадра прошла успешно")
    
    # Демонстрируем обнаружение ошибки
    print("\n--- Проверка обнаружения ошибок ---")
    corrupted = bytearray(frame)
    corrupted[0] ^= 0x01
    is_valid = verify_ip_checksum(corrupted)
    print_result(not is_valid, "Одиночная ошибка обнаружена")
    
    return frame


def demo_fletcher():
    """Демонстрация контрольной суммы Флетчера"""
    print_header("Контрольная сумма Флетчера")
    
    message = input("Введите сообщение (или нажмите Enter для примера): ").strip()
    if not message:
        message = "Hello, World!"
        print(f"Используем пример: {message}")
    
    message_bytes = message.encode('utf-8')
    fletcher16 = fletcher_16(message_bytes)
    fletcher32 = fletcher_32(message_bytes)
    
    print(f"\nИсходное сообщение: {message}")
    print(f"Fletcher-16: {fletcher16:04X}")
    print(f"Fletcher-32: {fletcher32:08X}")
    
    # Демонстрируем чувствительность к перестановке
    print("\n--- Чувствительность к перестановке данных ---")
    message2 = "World, " + message.replace("World, ", "") if "World" in message else message[::-1]
    if len(message2) != len(message):
        message2 = message[::-1]
    
    print(f"Переставленное сообщение: {message2}")
    fletcher16_2 = fletcher_16(message2.encode())
    print(f"Fletcher-16 для переставленного: {fletcher16_2:04X}")
    
    if fletcher16_2 != fletcher16:
        print_result(True, "Обнаружена перестановка данных")
    else:
        print_result(False, "Не обнаружена перестановка данных")
    
    # Сравнение с простой суммой
    simple_sum = sum(message_bytes) % 65536
    simple_sum2 = sum(message2.encode()) % 65536
    print(f"\nПростая сумма (для сравнения):")
    print(f"  Исходное: {simple_sum:04X}")
    print(f"  Переставленное: {simple_sum2:04X}")
    if simple_sum == simple_sum2:
        print("  ⚠️ Простая сумма НЕ обнаружила перестановку!")
    else:
        print("  ✅ Простая сумма обнаружила перестановку")


def demo_crc():
    """Демонстрация CRC"""
    print_header("CRC (Циклический избыточный код)")
    
    print("Выберите тип CRC:")
    print("1. CRC-32 (Ethernet) - рекомендуется")
    print("2. CRC-16")
    print("3. CRC-8")
    
    choice = input("Ваш выбор (1-3): ").strip()
    
    if choice == '1':
        crc = CRC(CRC.CRC_32_IEEE)
        crc_name = "CRC-32"
    elif choice == '2':
        crc = CRC(CRC.CRC_16, initial_value=0xFFFF, final_xor=0xFFFF)
        crc_name = "CRC-16"
    elif choice == '3':
        crc = CRC(CRC.CRC_8, initial_value=0x00, final_xor=0x00)
        crc_name = "CRC-8"
    else:
        print("Выбран CRC-32 по умолчанию")
        crc = CRC(CRC.CRC_32_IEEE)
        crc_name = "CRC-32"
    
    message = input("Введите сообщение (или нажмите Enter для примера): ").strip()
    if not message:
        message = "1101011111"
        print(f"Используем пример: {message}")
    
    message_bytes = message.encode('utf-8')
    crc_value = crc.calculate(message_bytes)
    
    print(f"\nИсходные данные: {message}")
    print(f"{crc_name}: {crc_value:0{2 * (crc.width // 4)}X}")
    
    # Добавляем CRC
    frame = crc.add_crc(message_bytes)
    print(f"Кадр для передачи (hex): {frame.hex()}")
    
    # Проверяем
    is_valid = crc.verify(frame)
    print_result(is_valid, "Проверка кадра прошла успешно")
    
    # Демонстрируем обнаружение ошибок
    print("\n--- Проверка обнаружения ошибок ---")
    
    # Одиночная ошибка
    corrupted = bytearray(frame)
    corrupted[0] ^= 0x01
    is_valid = crc.verify(corrupted)
    print_result(not is_valid, "Одиночная ошибка обнаружена")
    
    # Пакет ошибок
    if len(corrupted) > 2:
        corrupted[1] ^= 0x07
        is_valid = crc.verify(corrupted)
        print_result(not is_valid, "Пакет ошибок (3 бита) обнаружен")
    
    # Информация о возможностях CRC
    print(f"\n--- Возможности {crc_name} ---")
    print(f"  • Обнаруживает все одиночные ошибки")
    print(f"  • Обнаруживает все пакеты ошибок длиной ≤ {crc.width}")
    print(f"  • Обнаруживает все ошибки с нечетным количеством битов")
    print(f"  • Вероятность пропуска случайной ошибки: 1/2^{crc.width}")


def demo_comparison():
    """Сравнение всех методов"""
    print_header("Сравнение методов обнаружения ошибок")
    
    original = input("Введите сообщение для тестирования (Enter для примера): ").strip()
    if not original:
        original = "Hello, World! Test message."
        print(f"Используем пример: {original}")
    
    original_bytes = original.encode('utf-8')
    
    # Тестовые сценарии
    test_cases = [
        ("Оригинал", original_bytes),
        ("Одиночная ошибка", bytearray(original_bytes)),
        ("Две ошибки", bytearray(original_bytes)),
        ("Перестановка", bytearray(original_bytes)),
        ("Добавление нуля", bytearray(original_bytes)),
        ("Пакет ошибок", bytearray(original_bytes))
    ]
    
    # Создаем модификации
    single_error = bytearray(original_bytes)
    if len(single_error) > 5:
        single_error[5] ^= 0x01
    test_cases[1] = ("Одиночная ошибка", single_error)
    
    double_error = bytearray(original_bytes)
    if len(double_error) > 5:
        double_error[2] ^= 0x01
        double_error[18 % len(double_error)] ^= 0x01
    test_cases[2] = ("Две ошибки", double_error)
    
    swapped = bytearray(original_bytes)
    if len(swapped) >= 4:
        swapped[0:2], swapped[2:4] = swapped[2:4], swapped[0:2]
    test_cases[3] = ("Перестановка", swapped)
    
    with_zero = bytearray(original_bytes)
    with_zero.insert(10, 0)
    test_cases[4] = ("Добавление нуля", with_zero)
    
    burst = bytearray(original_bytes)
    if len(burst) > 10:
        burst[10] ^= 0x1F
    test_cases[5] = ("Пакет ошибок", burst)
    
    # Создаем экземпляр CRC
    crc32 = CRC(CRC.CRC_32_IEEE)
    
    # Таблица результатов
    print(f"\n{'Тип ошибки':<20} {'IP Checksum':<15} {'Fletcher-16':<15} {'CRC-32':<15}")
    print("-" * 65)
    
    for error_type, data in test_cases:
        data_bytes = bytes(data)
        
        # IP Checksum
        ip_frame = data_bytes + calculate_ip_checksum(data_bytes).to_bytes(2, 'big')
        ip_ok = verify_ip_checksum(ip_frame)
        
        # Fletcher
        fletcher_val = fletcher_16(data_bytes)
        fletcher_frame = data_bytes + fletcher_val.to_bytes(2, 'big')
        fletcher_ok = verify_fletcher(fletcher_frame)
        
        # CRC
        crc_frame = crc32.add_crc(data_bytes)
        crc_ok = crc32.verify(crc_frame)
        
        if error_type == "Оригинал":
            ip_result = "✅ OK" if ip_ok else "❌ Ошибка"
            fletcher_result = "✅ OK" if fletcher_ok else "❌ Ошибка"
            crc_result = "✅ OK" if crc_ok else "❌ Ошибка"
        else:
            ip_result = "✅ Не обнар." if ip_ok else "❌ Обнаружена"
            fletcher_result = "✅ Не обнар." if fletcher_ok else "❌ Обнаружена"
            crc_result = "✅ Не обнар." if crc_ok else "❌ Обнаружена"
        
        print(f"{error_type:<20} {ip_result:<15} {fletcher_result:<15} {crc_result:<15}")


def demo_crc_division():
    """Демонстрация процесса CRC деления (как в тексте)"""
    print_header("Демонстрация CRC деления (как на илл. 3.9)")
    
    def crc_division(dividend, divisor):
        """Выполняет деление по модулю 2"""
        dividend_list = list(dividend)
        divisor_len = len(divisor)
        temp = dividend_list.copy()
        
        print(f"\nДелимое: {''.join(dividend_list)}")
        print(f"Делитель: {divisor}")
        print("\nПроцесс деления:")
        
        for i in range(len(temp) - divisor_len + 1):
            if temp[i] == '1':
                print(f"  Шаг {i+1}: {''.join(temp)}")
                print(f"          XOR {divisor}{' ' * (len(temp) - divisor_len - i)}")
                for j in range(divisor_len):
                    temp[i + j] = str(int(temp[i + j]) ^ int(divisor[j]))
                print(f"          = {''.join(temp)}")
        
        remainder = ''.join(temp[-(divisor_len - 1):])
        return remainder
    
    frame = "1101011111"
    generator = "10011"  # x^4 + x + 1
    
    print(f"\nФрейм: {frame}")
    print(f"Образующий многочлен G(x): {generator}")
    
    r = len(generator) - 1
    extended_frame = frame + "0" * r
    print(f"\n1. Добавляем {r} нулей: {extended_frame}")
    
    remainder = crc_division(extended_frame, generator)
    print(f"\nОстаток от деления: {remainder}")
    
    transmitted = frame + remainder
    print(f"\n2. Передаваемый кадр T(x): {transmitted}")
    
    print(f"\n3. Проверка на приемной стороне:")
    check_remainder = crc_division(transmitted, generator)
    print(f"\nОстаток от деления принятого кадра: {check_remainder}")
    
    if int(check_remainder) == 0:
        print("\n✅ Остаток = 0 → ошибок нет")
    else:
        print("\n❌ Остаток ≠ 0 → обнаружена ошибка")


# ==================== ГЛАВНОЕ МЕНЮ ====================

def main():
    """Главная функция программы"""
    clear_screen()
    
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 20 + "ОБНАРУЖЕНИЕ ОШИБОК В ПЕРЕДАЧЕ ДАННЫХ" + " " * 20 + "║")
    print("╚" + "=" * 68 + "╝")
    print("\nПрограмма реализует три основных метода обнаружения ошибок:")
    print("  • IP-контрольная сумма (16-бит, обратный код)")
    print("  • Контрольная сумма Флетчера (с учетом позиции данных)")
    print("  • CRC (Циклический избыточный код)")
    
    while True:
        print("\n" + "─" * 70)
        print("\nГЛАВНОЕ МЕНЮ:")
        print("  1. IP-контрольная сумма")
        print("  2. Контрольная сумма Флетчера")
        print("  3. CRC (циклический избыточный код)")
        print("  4. Сравнить все методы")
        print("  5. Демонстрация CRC деления (как в тексте)")
        print("  6. Информация о методах")
        print("  0. Выход")
        print("─" * 70)
        
        choice = input("\nВаш выбор (0-6): ").strip()
        
        if choice == '0':
            print("\nДо свидания!")
            sys.exit(0)
        elif choice == '1':
            demo_ip_checksum()
            input("\nНажмите Enter для продолжения...")
        elif choice == '2':
            demo_fletcher()
            input("\nНажмите Enter для продолжения...")
        elif choice == '3':
            demo_crc()
            input("\nНажмите Enter для продолжения...")
        elif choice == '4':
            demo_comparison()
            input("\nНажмите Enter для продолжения...")
        elif choice == '5':
            demo_crc_division()
            input("\nНажмите Enter для продолжения...")
        elif choice == '6':
            print_header("Информация о методах обнаружения ошибок")
            print("""
                IP-КОНТРОЛЬНАЯ СУММА:
                • 16-битная контрольная сумма с обратным кодом
                • Используется в IP-пакетах интернета
                • Обнаруживает одиночные ошибки и ошибки в 16-битных словах
                • Не обнаруживает перестановки данных и добавление нулей

                КОНТРОЛЬНАЯ СУММА ФЛЕТЧЕРА:
                • Учитывает позицию данных в сообщении
                • Обнаруживает перестановки данных
                • Существует в 16-битном и 32-битном вариантах
                • Более надежна, чем простая сумма

                CRC (ЦИКЛИЧЕСКИЙ ИЗБЫТОЧНЫЙ КОД):
                • Самый надежный метод обнаружения ошибок
                • Используется в Ethernet, Wi-Fi, SONET
                • Обнаруживает все пакеты ошибок длиной до 32 бит
                • Вероятность пропуска ошибки: 1/2^32 (для CRC-32)
                • Основан на делении полиномов по модулю 2
            """)
            input("\nНажмите Enter для продолжения...")
        else:
            print("❌ Неверный выбор. Пожалуйста, выберите 0-6.")
    
    clear_screen()


# ==================== ЗАПУСК ПРОГРАММЫ ====================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nПрограмма прервана пользователем.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Ошибка: {e}")
        input("\nНажмите Enter для выхода...")
        sys.exit(1)