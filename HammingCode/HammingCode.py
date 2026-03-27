import itertools
import math

class HammingCode:
    """
    Реализация кода Хэмминга для (7,4) без NumPy
    """
    
    def __init__(self):
        self.m = 4  # информационные биты
        self.r = 3  # контрольные биты
        self.n = self.m + self.r
        
        # Генерирующая матрица G (4x7) в систематической форме
        self.G = [
            [1, 0, 0, 0, 1, 1, 0],  # 1-й инф. бит
            [0, 1, 0, 0, 1, 0, 1],  # 2-й инф. бит
            [0, 0, 1, 0, 0, 1, 1],  # 3-й инф. бит
            [0, 0, 0, 1, 1, 1, 1]   # 4-й инф. бит
        ]
        
        # Проверочная матрица H (3x7)
        self.H = [
            [1, 0, 1, 0, 1, 0, 1],  # проверка для позиций 1,3,5,7
            [0, 1, 1, 0, 0, 1, 1],  # проверка для позиций 2,3,6,7
            [0, 0, 0, 1, 1, 1, 1]   # проверка для позиций 4,5,6,7
        ]
    
    def mod2_multiply(self, vector, matrix):
        """Умножение вектора на матрицу по модулю 2"""
        result = []
        for j in range(len(matrix[0])):  # для каждого столбца
            s = 0
            for i in range(len(vector)):  # для каждого элемента вектора
                if i < len(matrix) and j < len(matrix[i]):
                    s += vector[i] * matrix[i][j]
            result.append(s % 2)
        return result
    
    def mod2_matrix_multiply(self, matrix, vector):
        """Умножение матрицы на вектор по модулю 2 (для синдрома)"""
        result = []
        for i in range(len(matrix)):
            s = 0
            for j in range(len(vector)):
                if j < len(matrix[i]):
                    s += matrix[i][j] * vector[j]
            result.append(s % 2)
        return result
    
    def encode(self, data_bits):
        """Кодирование 4 бит данных в 7-битное кодовое слово"""
        if len(data_bits) != self.m:
            raise ValueError(f"Ожидается {self.m} бит, получено {len(data_bits)}")
        
        return self.mod2_multiply(data_bits, self.G)
    
    def decode(self, received_bits):
        """Декодирование с исправлением одиночной ошибки"""
        if len(received_bits) != self.n:
            raise ValueError(f"Ожидается {self.n} бит, получено {len(received_bits)}")
        
        # Вычисление синдрома
        syndrome = self.mod2_matrix_multiply(self.H, received_bits)
        
        # Преобразование синдрома в число (позицию ошибки)
        error_position = 0
        for i in range(len(syndrome)):
            if syndrome[i] == 1:
                error_position += 2**i
        
        corrected_bits = received_bits.copy()
        
        if error_position > 0 and error_position <= self.n:
            # Инвертируем бит с ошибкой
            corrected_bits[error_position - 1] ^= 1
            error_fixed = True
        else:
            error_fixed = False
        
        # Извлечение информационных битов
        data_bits = corrected_bits[:self.m]
        
        return data_bits, corrected_bits, syndrome, error_position, error_fixed
    
    def calculate_hamming_distance(self, word1, word2):
        """Вычисление расстояния Хэмминга между двумя словами"""
        if len(word1) != len(word2):
            raise ValueError("Слова должны быть одинаковой длины")
        
        distance = 0
        for b1, b2 in zip(word1, word2):
            if b1 != b2:
                distance += 1
        return distance


class CodeAnalyzer:
    """
    Класс для анализа кодов
    """
    
    @staticmethod
    def check_hamming_bound(m, r):
        """Проверка границы Хэмминга (m + r + 1) <= 2^r"""
        left = m + r + 1
        right = 2 ** r
        return left <= right, left, right
    
    @staticmethod
    def calculate_capabilities(d_min):
        """Расчет возможностей кода на основе минимального расстояния"""
        detect = d_min - 1
        correct = (d_min - 1) // 2
        return detect, correct
    
    @staticmethod
    def find_min_distance(codewords):
        """Поиск минимального расстояния Хэмминга"""
        min_dist = float('inf')
        pairs = []
        
        for i, j in itertools.combinations(range(len(codewords)), 2):
            dist = 0
            for k in range(len(codewords[i])):
                if codewords[i][k] != codewords[j][k]:
                    dist += 1
            
            if dist < min_dist:
                min_dist = dist
                pairs = [(i, j)]
            elif dist == min_dist:
                pairs.append((i, j))
        
        return min_dist, pairs


def demonstrate_hamming_74():
    """Демонстрация работы кода Хэмминга (7,4)"""
    print("\n" + "=" * 60)
    print("ДЕМОНСТРАЦИЯ КОДА ХЭММИНГА (7,4)")
    print("=" * 60)
    
    hamming = HammingCode()
    
    # Проверка границы Хэмминга
    print("\n1. ПРОВЕРКА ГРАНИЦЫ ХЭММИНГА:")
    bound_ok, left, right = CodeAnalyzer.check_hamming_bound(4, 3)
    print(f"   (m + r + 1) = (4 + 3 + 1) = {left} <= 2^{3} = {right} -> {bound_ok}")
    print(f"   Граница {'достигнута' if bound_ok and left == right else 'выполнена'}")
    
    # Тестовые данные
    test_data = [
        [0, 0, 0, 0],
        [0, 0, 0, 1],
        [0, 1, 0, 1],
        [1, 0, 0, 0],
        [1, 0, 0, 1],
        [1, 1, 1, 1],
    ]
    
    print("\n2. КОДИРОВАНИЕ И АНАЛИЗ КОДОВЫХ СЛОВ:")
    codewords = []
    
    for i, data in enumerate(test_data):
        codeword = hamming.encode(data)
        codewords.append(codeword)
        
        data_str = ''.join(map(str, data))
        code_str = ''.join(map(str, codeword))
        print(f"   Данные {data_str} -> Кодовое слово: {code_str}")
    
    print("\n3. РАССТОЯНИЕ ХЭММИНГА:")
    min_dist, pairs = CodeAnalyzer.find_min_distance(codewords)
    print(f"   Минимальное кодовое расстояние: d_min = {min_dist}")
    
    detect, correct = CodeAnalyzer.calculate_capabilities(min_dist)
    print(f"   Возможности кода: обнаруживает до {detect} ошибок, " f"исправляет до {correct} ошибок")
    
    print("\n4. СИМУЛЯЦИЯ ОШИБОК И ДЕКОДИРОВАНИЕ:")
    
    original_data = [0, 0, 0, 1]
    codeword = hamming.encode(original_data)
    
    print(f"\n   Оригинал: данные={original_data}, кодовое слово={codeword}")
    
    error_positions = [2, 4, 6]
    
    for err_pos in error_positions:
        received = codeword.copy()
        received[err_pos] ^= 1
        
        print(f"\n   Ошибка в позиции {err_pos+1}: получено {received}")
        
        decoded_data, corrected, syndrome, err_pos_found, fixed = hamming.decode(received)
        
        print(f"   Синдром: {syndrome} -> позиция ошибки: {err_pos_found}")
        print(f"   Исправленное слово: {corrected}")
        print(f"   Декодированные данные: {decoded_data}")
        print(f"   Результат: {'исправлено' if fixed else 'ошибок не найдено'}")


def demonstrate_error_detection_example():
    """Пример из текста с 4 кодовыми словами"""
    print("\n" + "=" * 60)
    print("ПРИМЕР ИЗ ТЕКСТА: Код с 4 кодовыми словами")
    print("=" * 60)
    
    codewords_list = [
        [0,0,0,0,0,0,0,0,0,0],
        [0,0,0,0,0,1,1,1,1,1],
        [1,1,1,1,1,0,0,0,0,0],
        [1,1,1,1,1,1,1,1,1,1],
    ]
    
    print("\nДопустимые кодовые комбинации:")
    names = ["A", "B", "C", "D"]
    for i, cw in enumerate(codewords_list):
        print(f"{names[i]}: {cw}")
    
    print("\nРасстояния Хэмминга между кодовыми словами:")
    hamming = HammingCode()
    
    for i, j in itertools.combinations(range(4), 2):
        dist = hamming.calculate_hamming_distance(codewords_list[i], codewords_list[j])
        print(f"  {names[i]}-{names[j]}: {dist}")
    
    min_dist, _ = CodeAnalyzer.find_min_distance(codewords_list)
    print(f"\nМинимальное кодовое расстояние: d_min = {min_dist}")
    
    detect, correct = CodeAnalyzer.calculate_capabilities(min_dist)
    print(f"Способности кода: обнаруживает до {detect} ошибок, " f"исправляет до {correct} ошибок")
    
    print("\nСимуляция получения слова 0000000111:")
    received = [0,0,0,0,0,0,0,1,1,1]
    
    print(f"Получено: {received}")
    print("Поиск ближайшего кодового слова:")
    
    min_dist = float('inf')
    best_match = -1
    
    for i, cw in enumerate(codewords_list):
        dist = hamming.calculate_hamming_distance(received, cw)
        print(f"  До {names[i]}: {dist}")
        if dist < min_dist:
            min_dist = dist
            best_match = i
    
    print(f"\nБлижайшее кодовое слово: {names[best_match]} = {codewords_list[best_match]}")


def main():
    """Главная функция программы"""
    print("=" * 70)
    print("МОДЕЛИРОВАНИЕ ПОМЕХОУСТОЙЧИВОГО КОДИРОВАНИЯ")
    print("(Версия без NumPy)")
    print("=" * 70)
    
    print("\n--- ОСНОВНЫЕ ПОНЯТИЯ ИЗ ТЕКСТА ---")
    print("• Линейный код: контрольные биты = линейная функция от данных")
    print("• Систематический код: данные передаются напрямую")
    print("• Блочный код (n, m): n = m + r")
    print("• Скорость кода = m/n")
    
    demonstrate_hamming_74()
    demonstrate_error_detection_example()
    
    print("\n" + "=" * 70)
    print("ВЫВОДЫ:")
    print("• Коды Хэмминга эффективны для каналов с одиночными ошибками")
    print("• Расстояние Хэмминга определяет корректирующую способность кода")
    print("=" * 70)


if __name__ == "__main__":
    main()