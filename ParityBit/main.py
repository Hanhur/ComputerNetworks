import random
from typing import List, Tuple
from dataclasses import dataclass

# Базовые классы для работы с битами и кодами

@dataclass
class TransmissionResult:
    """Результат передачи данных"""
    data: List[int]
    errors_detected: bool
    errors_corrected: int
    parity_bits_used: int
    retransmissions: int = 0

class BitOperations:
    """Вспомогательные операции с битами"""
    
    @staticmethod
    def generate_random_bits(length: int) -> List[int]:
        """Генерация случайной последовательности битов"""
        return [random.randint(0, 1) for _ in range(length)]
    
    @staticmethod
    def introduce_errors(bits: List[int], error_probability: float) -> Tuple[List[int], int]:
        """Внесение изолированных ошибок с заданной вероятностью"""
        result = bits.copy()
        error_count = 0
        for i in range(len(result)):
            if random.random() < error_probability:
                result[i] ^= 1  # Инвертируем бит
                error_count += 1
        return result, error_count
    
    @staticmethod
    def introduce_burst_errors(bits: List[int], burst_length: int) -> Tuple[List[int], int, int]:
        """Внесение пакета ошибок (последовательности длиной burst_length)"""
        result = bits.copy()
        start_pos = random.randint(0, len(bits) - burst_length)
        errors_injected = 0
        for i in range(start_pos, start_pos + burst_length):
            # Инвертируем с вероятностью 0.5 (не все биты обязательно меняются)
            if random.random() < 0.5:
                result[i] ^= 1
                errors_injected += 1
        return result, start_pos, errors_injected
    
    @staticmethod
    def calculate_parity(bits: List[int], even_parity: bool = True) -> int:
        """Вычисление бита четности"""
        parity = sum(bits) % 2
        return parity if even_parity else (1 - parity)
    
    @staticmethod
    def verify_parity(bits: List[int], parity_bit: int, even_parity: bool = True) -> bool:
        """Проверка бита четности"""
        expected_parity = BitOperations.calculate_parity(bits, even_parity)
        return expected_parity == parity_bit

class HammingCode:
    """Код Хэмминга для исправления одиночных ошибок"""
    
    @staticmethod
    def calculate_parity_bits(data_length: int) -> int:
        """Расчет количества контрольных битов для кода Хэмминга"""
        r = 1
        while (1 << r) < data_length + r + 1:
            r += 1
        return r
    
    @staticmethod
    def encode(data: List[int]) -> List[int]:
        """Кодирование данных кодом Хэмминга"""
        n = len(data)
        r = HammingCode.calculate_parity_bits(n)
        total_length = n + r
        
        # Инициализация кодового слова
        code = [0] * total_length
        
        # Заполнение позиций данных (пропуская степени двойки)
        data_pos = 0
        for i in range(1, total_length + 1):
            if (i & (i - 1)) != 0:  # Не степень двойки
                code[i - 1] = data[data_pos]
                data_pos += 1
        
        # Вычисление контрольных битов
        for i in range(r):
            parity_pos = (1 << i) - 1
            parity = 0
            for j in range(parity_pos + 1, total_length + 1):
                if j & (1 << i):
                    parity ^= code[j - 1]
            code[parity_pos] = parity
        
        return code
    
    @staticmethod
    def decode(code: List[int]) -> Tuple[List[int], int, bool]:
        """Декодирование и исправление ошибок"""
        total_length = len(code)
        r = 0
        while (1 << r) < total_length + 1:
            r += 1
        
        # Вычисление синдрома
        syndrome = 0
        for i in range(r):
            parity_pos = (1 << i) - 1
            parity = code[parity_pos]
            calculated = 0
            for j in range(parity_pos + 1, total_length + 1):
                if j & (1 << i):
                    calculated ^= code[j - 1]
            if parity != calculated:
                syndrome += (1 << i)
        
        errors_corrected = 0
        error_detected = False
        
        # Исправление ошибки, если она есть
        if syndrome != 0:
            error_detected = True
            if syndrome <= total_length:
                code[syndrome - 1] ^= 1
                errors_corrected = 1
        
        # Извлечение данных
        data = []
        for i in range(1, total_length + 1):
            if (i & (i - 1)) != 0:  # Не степень двойки
                data.append(code[i - 1])
        
        return data, errors_corrected, error_detected

class ParityChannel:
    """Канал с битом четности и повторной передачей"""
    
    def __init__(self, data_length: int = 1000, error_probability: float = 1e-6, even_parity: bool = True):
        self.data_length = data_length
        self.error_probability = error_probability
        self.even_parity = even_parity
        self.total_bits_sent = 0
        self.total_errors = 0
        
    def send_block(self, data: List[int]) -> Tuple[TransmissionResult, int]:
        """Отправка блока данных с битом четности"""
        # Вычисляем бит четности
        parity_bit = BitOperations.calculate_parity(data, self.even_parity)
        
        # Формируем кодовое слово
        codeword = data + [parity_bit]
        self.total_bits_sent += len(codeword)
        
        # Вносим ошибки при передаче
        received, error_count = BitOperations.introduce_errors(codeword, self.error_probability)
        self.total_errors += error_count
        
        # Проверяем четность
        received_data = received[:-1]
        received_parity = received[-1]
        
        error_detected = not BitOperations.verify_parity(
            received_data, received_parity, self.even_parity
        )
        
        return TransmissionResult(
            data=received_data if not error_detected else data,
            errors_detected=error_detected,
            errors_corrected=0,
            parity_bits_used=1,
            retransmissions=0
        ), error_count
    
    def transmit_with_arq(self, data_blocks: List[List[int]]) -> Tuple[List[List[int]], int, int, int]:
        """Передача данных с автоматическим запросом повторения"""
        received_blocks = []
        total_retransmissions = 0
        total_bits = 0
        total_errors = 0
        
        for block in data_blocks:
            result, errors = self.send_block(block)
            total_bits += len(block) + 1
            total_errors += errors
            
            retries = 0
            while result.errors_detected and retries < 10:
                total_retransmissions += 1
                retries += 1
                result, errors = self.send_block(block)
                total_bits += len(block) + 1
                total_errors += errors
            
            if result.errors_detected:
                received_blocks.append(result.data)
            else:
                received_blocks.append(result.data)
            
            result.retransmissions = retries
        
        return received_blocks, total_retransmissions, total_bits, total_errors

class HammingChannel:
    """Канал с исправлением ошибок кодом Хэмминга"""
    
    def __init__(self, data_length: int = 1000, error_probability: float = 1e-6):
        self.data_length = data_length
        self.error_probability = error_probability
        self.r = HammingCode.calculate_parity_bits(data_length)
        self.total_bits_sent = 0
        self.total_errors = 0
        
    def send_block(self, data: List[int]) -> Tuple[TransmissionResult, int]:
        """Отправка блока данных с кодом Хэмминга"""
        # Кодируем данные
        codeword = HammingCode.encode(data)
        self.total_bits_sent += len(codeword)
        
        # Вносим ошибки
        received, error_count = BitOperations.introduce_errors(codeword, self.error_probability)
        self.total_errors += error_count
        
        # Декодируем с исправлением
        decoded_data, errors_corrected, error_detected = HammingCode.decode(received)
        
        return TransmissionResult(
            data=decoded_data,
            errors_detected=error_detected,
            errors_corrected=errors_corrected,
            parity_bits_used=self.r,
            retransmissions=0
        ), error_count
    
    def transmit_all(self, data_blocks: List[List[int]]) -> Tuple[List[List[int]], int, int]:
        """Передача всех блоков"""
        received_blocks = []
        total_errors_detected = 0
        total_errors = 0
        
        for block in data_blocks:
            result, errors = self.send_block(block)
            received_blocks.append(result.data)
            total_errors += errors
            if result.errors_detected:
                total_errors_detected += 1
        
        return received_blocks, total_errors_detected, total_errors

class InterleavedParityChannel:
    """Канал с чередованием для борьбы с пакетами ошибок (без NumPy)"""
    
    def __init__(self, rows: int = 7, cols: int = 7, burst_length: int = 7):
        self.rows = rows
        self.cols = cols
        self.burst_length = burst_length
        
    def create_matrix(self, data: List[int], rows: int, cols: int) -> List[List[int]]:
        """Создание матрицы из списка"""
        matrix = []
        for i in range(rows):
            start = i * cols
            end = start + cols
            if end <= len(data):
                row = data[start:end]
                matrix.append(row)
            else:
                # Если данных недостаточно, дополняем нулями
                row = data[start:] + [0] * (cols - len(data[start:]))
                matrix.append(row)
        return matrix
    
    def flatten_matrix(self, matrix: List[List[int]]) -> List[int]:
        """Преобразование матрицы в список"""
        return [item for row in matrix for item in row]
    
    def interleave(self, data: List[int]) -> List[int]:
        """Чередование данных (запись по строкам, чтение по столбцам)"""
        # Формируем матрицу rows x cols
        matrix = self.create_matrix(data[:self.rows * self.cols], self.rows, self.cols)
        
        # Читаем по столбцам
        interleaved = []
        for col in range(self.cols):
            for row in range(self.rows):
                if row < len(matrix) and col < len(matrix[row]):
                    interleaved.append(matrix[row][col])
        
        return interleaved
    
    def deinterleave(self, data: List[int]) -> List[int]:
        """Восстановление порядка данных"""
        # Создаем матрицу для восстановления
        matrix = [[0] * self.cols for _ in range(self.rows)]
        
        # Заполняем по столбцам
        idx = 0
        for col in range(self.cols):
            for row in range(self.rows):
                if idx < len(data):
                    matrix[row][col] = data[idx]
                    idx += 1
        
        # Читаем по строкам
        deinterleaved = []
        for row in range(self.rows):
            for col in range(self.cols):
                deinterleaved.append(matrix[row][col])
        
        return deinterleaved
    
    def add_column_parity(self, data: List[int]) -> List[int]:
        """Добавление битов четности для каждого столбца"""
        # Формируем матрицу rows x cols
        matrix = self.create_matrix(data[:self.rows * self.cols], self.rows, self.cols)
        
        # Вычисляем четность для каждого столбца
        parity_bits = []
        for col in range(self.cols):
            column_sum = sum(matrix[row][col] for row in range(self.rows))
            parity = column_sum % 2
            parity_bits.append(parity)
        
        # Добавляем строку четности
        matrix.append(parity_bits)
        
        # Возвращаем как плоский список
        return self.flatten_matrix(matrix)
    
    def transmit_with_interleaving(self, data: List[int]) -> Tuple[List[int], bool, int, int]:
        """Передача с чередованием для защиты от пакетов ошибок"""
        original_length = len(data)
        
        # Убеждаемся, что данные имеют правильный размер
        required_size = self.rows * self.cols
        if len(data) > required_size:
            data = data[:required_size]
        elif len(data) < required_size:
            data = data + [0] * (required_size - len(data))
        
        # Добавляем четность столбцов
        with_parity = self.add_column_parity(data)
        
        # Чередуем
        interleaved = self.interleave(with_parity)
        
        # Вносим пакет ошибок
        corrupted, burst_start, errors_injected = BitOperations.introduce_burst_errors(
            interleaved, self.burst_length
        )
        
        # Восстанавливаем порядок
        deinterleaved = self.deinterleave(corrupted)
        
        # Проверяем четность столбцов
        # Формируем матрицу (rows+1) x cols
        matrix = self.create_matrix(deinterleaved[: (self.rows + 1) * self.cols], 
                                   self.rows + 1, self.cols)
        
        errors_detected = False
        for col in range(self.cols):
            if col < len(matrix[0]):  # Проверяем существование столбца
                column_sum = sum(matrix[row][col] for row in range(self.rows))
                if self.rows < len(matrix):  # Проверяем существование строки четности
                    parity = matrix[self.rows][col]
                    if column_sum % 2 != parity:
                        errors_detected = True
                        break
        
        # Восстанавливаем данные (без строки четности)
        recovered_data = []
        for row in range(self.rows):
            for col in range(self.cols):
                if row < len(matrix) and col < len(matrix[row]):
                    recovered_data.append(matrix[row][col])
        
        # Обрезаем до исходной длины
        recovered_data = recovered_data[:original_length]
        
        return recovered_data, errors_detected, burst_start, errors_injected

class ComparativeAnalysis:
    """Сравнительный анализ методов"""
    
    def __init__(self, data_size_mbits: float = 1.0, block_size: int = 1000, error_prob: float = 1e-6):
        self.data_size_bits = int(data_size_mbits * 1_000_000)
        self.block_size = block_size
        self.error_prob = error_prob
        self.num_blocks = self.data_size_bits // block_size
        
    def run_comparison(self) -> dict:
        """Запуск сравнения методов"""
        print("Генерация тестовых данных...")
        # Генерируем данные
        all_data = [BitOperations.generate_random_bits(self.block_size) 
                    for _ in range(self.num_blocks)]
        
        print("Тестирование метода Parity + ARQ...")
        # 1. Метод с битом четности + ARQ
        parity_channel = ParityChannel(self.block_size, self.error_prob)
        received_parity, retransmissions, total_bits_parity, total_errors_parity = parity_channel.transmit_with_arq(all_data)
        
        print("Тестирование метода Хэмминга...")
        # 2. Метод с кодом Хэмминга
        hamming_channel = HammingChannel(self.block_size, self.error_prob)
        received_hamming, uncorrected_errors, total_errors_hamming = hamming_channel.transmit_all(all_data)
        
        print("Тестирование метода с чередованием...")
        # 3. Метод с чередованием
        interleaved_channel = InterleavedParityChannel(rows=10, cols=10, burst_length=10)
        # Для чередования используем один блок для демонстрации
        test_data = BitOperations.generate_random_bits(100)
        recovered, burst_detected, burst_pos, errors_injected = interleaved_channel.transmit_with_interleaving(test_data)
        
        # Расчет накладных расходов
        overhead_parity = total_bits_parity - self.data_size_bits
        overhead_hamming = hamming_channel.total_bits_sent - self.data_size_bits
        
        # Подсчет ошибок в принятых данных
        data_errors_parity = sum(1 for i, r in enumerate(received_parity) if r != all_data[i])
        
        result = {
            'method': 'Parity + ARQ',
            'overhead_bits': overhead_parity,
            'overhead_percent': (overhead_parity / self.data_size_bits) * 100,
            'retransmissions': retransmissions,
            'errors_detected': data_errors_parity,
            'total_channel_errors': total_errors_parity,
            'total_bits_sent': total_bits_parity
        }
        
        result2 = {
            'method': 'Hamming Code (FEC)',
            'overhead_bits': overhead_hamming,
            'overhead_percent': (overhead_hamming / self.data_size_bits) * 100,
            'uncorrected_errors': uncorrected_errors,
            'parity_bits_per_block': hamming_channel.r,
            'total_channel_errors': total_errors_hamming,
            'total_bits_sent': hamming_channel.total_bits_sent
        }
        
        result3 = {
            'method': 'Interleaved Parity',
            'burst_detected': burst_detected,
            'burst_position': burst_pos,
            'protection_length': interleaved_channel.burst_length,
            'errors_injected': errors_injected,
            'data_recovered_correctly': recovered == test_data[:len(recovered)]
        }
        
        return {'parity_arq': result, 'hamming': result2, 'interleaved': result3}
    
    def visualize_ascii(self, results: dict):
        """ASCII-визуализация результатов"""
        print("\n" + "=" * 70)
        print("ВИЗУАЛИЗАЦИЯ НАКЛАДНЫХ РАСХОДОВ")
        print("=" * 70)
        
        methods = ['Parity + ARQ', 'Hamming (FEC)']
        overheads = [results['parity_arq']['overhead_bits'], 
                     results['hamming']['overhead_bits']]
        
        max_overhead = max(overheads) if max(overheads) > 0 else 1
        bar_width = 50
        
        for method, overhead in zip(methods, overheads):
            bar_length = int((overhead / max_overhead) * bar_width)
            bar = '█' * bar_length + '░' * (bar_width - bar_length)
            print(f"\n{method:20} | {bar} | {overhead:,} бит")
            print(f"                     {overhead/1000:.1f} Кбит ({overhead/self.data_size_bits*100:.1f}% от данных)")

def demonstrate_burst_errors():
    """Демонстрация работы с пакетами ошибок"""
    print("\n" + "=" * 70)
    print("ДЕМОНСТРАЦИЯ БОРЬБЫ С ПАКЕТАМИ ОШИБОК МЕТОДОМ ЧЕРЕДОВАНИЯ")
    print("=" * 70)
    
    # Создаем тестовые данные
    rows, cols = 7, 7
    data_length = rows * cols
    original_data = BitOperations.generate_random_bits(data_length)
    
    print(f"\nРазмер блока: {rows} x {cols} = {data_length} бит")
    print(f"Исходные данные (первые 49 бит):")
    for i in range(0, min(49, data_length), 7):
        print(f"  Строка {i//7 + 1}: {original_data[i:i+7]}")
    
    # Создаем канал с чередованием
    channel = InterleavedParityChannel(rows=rows, cols=cols, burst_length=cols)
    
    # Передаем с пакетом ошибок
    recovered, error_detected, burst_pos, errors_injected = channel.transmit_with_interleaving(original_data)
    
    print(f"\nПакет ошибок внесен в позиции: {burst_pos} - {burst_pos + cols}")
    print(f"Фактически изменено битов: {errors_injected}")
    print(f"Ошибка обнаружена: {'ДА' if error_detected else 'НЕТ'}")
    print(f"Данные восстановлены верно: {'ДА' if recovered == original_data else 'НЕТ'}")
    
    # Демонстрация вероятности необнаружения
    print("\n" + "=" * 70)
    print("ВЕРОЯТНОСТЬ НЕОБНАРУЖЕНИЯ ОШИБКИ")
    print("=" * 70)
    print("Теоретическая вероятность необнаружения пакета ошибок:")
    print()
    
    for n in range(1, 9):
        probability = 2 ** (-n)
        print(f"  Для пакета длиной {n:2} бит: P(необнаружения) = 2^{-n} = {probability:.6f} ({probability*100:.4f}%)")

def main():
    """Основная функция для запуска сравнения"""
    print("=" * 70)
    print("СРАВНЕНИЕ МЕТОДОВ ОБНАРУЖЕНИЯ И ИСПРАВЛЕНИЯ ОШИБОК")
    print("=" * 70)
    print("\nПараметры эксперимента:")
    print(f"  • Объем данных: 1 Мбит (1,000,000 бит)")
    print(f"  • Размер блока: 1000 бит")
    print(f"  • Вероятность ошибки на бит: 10^-6")
    print(f"  • Количество блоков: 1000")
    
    # Запускаем анализ
    analyzer = ComparativeAnalysis(data_size_mbits=1.0, block_size=1000, error_prob=1e-6)
    results = analyzer.run_comparison()
    
    # Выводим результаты
    print("\n" + "=" * 70)
    print("РЕЗУЛЬТАТЫ СРАВНЕНИЯ")
    print("=" * 70)
    
    print("\n1. МЕТОД: БИТ ЧЕТНОСТИ + ПОВТОРНАЯ ПЕРЕДАЧА (ARQ)")
    print("-" * 60)
    print(f"  Накладные расходы:        {results['parity_arq']['overhead_bits']:,} бит")
    print(f"  Процент избыточности:     {results['parity_arq']['overhead_percent']:.2f}%")
    print(f"  Всего передано бит:       {results['parity_arq']['total_bits_sent']:,} бит")
    print(f"  Повторных передач:        {results['parity_arq']['retransmissions']}")
    print(f"  Ошибок в канале:          {results['parity_arq']['total_channel_errors']}")
    print(f"  Неисправленных ошибок:    {results['parity_arq']['errors_detected']}")
    
    print("\n2. МЕТОД: КОД ХЭММИНГА (FEC)")
    print("-" * 60)
    print(f"  Накладные расходы:        {results['hamming']['overhead_bits']:,} бит")
    print(f"  Процент избыточности:     {results['hamming']['overhead_percent']:.2f}%")
    print(f"  Всего передано бит:       {results['hamming']['total_bits_sent']:,} бит")
    print(f"  Контрольных битов/блок:   {results['hamming']['parity_bits_per_block']}")
    print(f"  Ошибок в канале:          {results['hamming']['total_channel_errors']}")
    print(f"  Неисправленных ошибок:    {results['hamming']['uncorrected_errors']}")
    
    print("\n3. МЕТОД: ЧЕРЕДОВАНИЕ ДЛЯ ПАКЕТОВ ОШИБОК")
    print("-" * 60)
    print(f"  Длина защищаемого пакета: {results['interleaved']['protection_length']} бит")
    print(f"  Обнаружение пакета:       {'ДА' if results['interleaved']['burst_detected'] else 'НЕТ'}")
    print(f"  Позиция пакета:           {results['interleaved']['burst_position']}")
    print(f"  Инвертировано битов:      {results['interleaved']['errors_injected']}")
    print(f"  Данные восстановлены:     {'ДА' if results['interleaved']['data_recovered_correctly'] else 'НЕТ'}")
    
    # ASCII-визуализация
    analyzer.visualize_ascii(results)
    
    # Демонстрация работы с пакетами ошибок
    demonstrate_burst_errors()
    
    # Теоретическое обоснование
    print("\n" + "=" * 70)
    print("ТЕОРЕТИЧЕСКОЕ ОБОСНОВАНИЕ")
    print("=" * 70)
    print("\nДля блока из 1000 бит с вероятностью ошибки 10^-6:")
    print(f"  • Ожидаемое количество ошибок на 1 Мбит: 1 ошибка")
    print(f"  • Накладные расходы ARQ: 2001 бит (1 бит четности × 1000 блоков + 1 повтор)")
    print(f"  • Накладные расходы Hamming: 10 000 бит (10 бит × 1000 блоков)")
    print(f"  • Экономия ARQ: {(10000 - 2001) / 10000 * 100:.1f}%")
    
    print("\n" + "=" * 70)
    print("ВЫВОД")
    print("=" * 70)
    print("В каналах с низкой вероятностью ошибки (10^-6 и ниже) и наличием")
    print("обратного канала, метод обнаружения ошибок с повторной передачей")
    print("(ARQ) эффективнее прямого исправления (FEC) за счет:")
    print("  • Меньших накладных расходов (в 5 раз меньше)")
    print("  • Адаптивности к уровню шума")
    print("  • Возможности борьбы с пакетами ошибок через чередование")
    print("\nКод Хэмминга оправдан только в случаях, когда:")
    print("  • Нет обратного канала (спутниковая связь, хранение данных)")
    print("  • Недопустимы задержки повторной передачи")
    print("  • Вероятность ошибок высока (более 10^-4)")

if __name__ == "__main__":
    random.seed(42)  # Для воспроизводимости результатов
    main()