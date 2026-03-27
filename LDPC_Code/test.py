"""
    ЕДИНАЯ ПРОГРАММА ДЛЯ ДЕМОНСТРАЦИИ ПОМЕХОУСТОЙЧИВЫХ КОДОВ
    =======================================================
    Объединяет: 
    1. Код Хэмминга (7,4)
    2. Сверточный код NASA (r=1/2, k=7)
    3. Код Рида-Соломона (графическая демонстрация)
    4. LDPC код (Low-Density Parity-Check)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import itertools
import math
import random
import sys
import os

# ==================== КЛАСС 1: КОД ХЭММИНГА ====================

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
        for j in range(len(matrix[0])):
            s = 0
            for i in range(len(vector)):
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


# ==================== КЛАСС 2: СВЕРТОЧНЫЙ КОД ====================

class ConvolutionalCode:
    """
    Симуляция сверточного кода NASA (r=1/2, k=7).
    Полиномы: 
        - G1 = 1111001 (171 в восьмеричной) -> для первого выходного бита
        - G2 = 1011011 (133 в восьмеричной) -> для второго выходного бита
    """
    
    def __init__(self):
        # Длина кодового ограничения (Constraint Length) = 7
        self.k = 7
        # Регистры памяти (6 штук + текущий бит, всего 7 состояний)
        self.registers = [0] * (self.k - 1)  # 6 регистров для хранения предыдущих битов
        
        # Полиномы (обратная связь регистров) для двух выходных битов
        # Индексы: 0 - текущий бит, 1-6 - регистры памяти
        self.g1 = [1, 1, 1, 1, 0, 0, 1]  # 171 octal (связи для первого выхода)
        self.g2 = [1, 0, 1, 1, 0, 1, 1]  # 133 octal (связи для второго выхода)
        
    def encode_bit(self, input_bit):
        """
        Кодирует один входной бит в два выходных бита.
        """
        # Формируем вектор состояния: [текущий_бит, рег1, рег2, ..., рег6]
        state = [input_bit] + self.registers
        
        # Вычисляем выходные биты через XOR (сумма по модулю 2)
        out1 = 0
        out2 = 0
        for i in range(self.k):
            if self.g1[i] == 1:
                out1 ^= state[i]  # XOR
            if self.g2[i] == 1:
                out2 ^= state[i]
        
        # Сдвигаем регистры (запоминаем текущий бит для будущих операций)
        self.registers.pop()  # Удаляем самый старый бит
        self.registers.insert(0, input_bit)  # Добавляем текущий бит в начало
        
        return out1, out2
    
    def encode_sequence(self, bits):
        """
        Кодирует последовательность битов.
        Для очистки памяти добавляем 6 нулей в конце (flushing).
        """
        self.reset()
        encoded = []
        original_length = len(bits)
        
        # Кодируем исходные биты
        for bit in bits:
            out1, out2 = self.encode_bit(bit)
            encoded.extend([out1, out2])
        
        # Добавляем 6 нулевых битов для очистки регистров (чтобы конечное состояние стало нулевым)
        for _ in range(self.k - 1):
            out1, out2 = self.encode_bit(0)
            encoded.extend([out1, out2])
            
        return encoded
    
    def reset(self):
        """Сброс регистров в начальное состояние."""
        self.registers = [0] * (self.k - 1)


class ViterbiDecoder:
    """
    Упрощенный декодер Витерби для сверточного кода (r=1/2, k=7).
    Поддерживает жесткое и мягкое декодирование.
    """
    
    def __init__(self):
        self.k = 7
        # Те же полиномы, что и у кодера
        self.g1 = [1, 1, 1, 1, 0, 0, 1]
        self.g2 = [1, 0, 1, 1, 0, 1, 1]
        
        # Предвычисляем все возможные переходы состояний
        self.num_states = 2 ** (self.k - 1)  # 64 состояния (от 0 до 63)
        self.next_states = {}  # Словарь: (текущее_состояние, входной_бит) -> следующее_состояние, выходные_биты
        self._init_state_transitions()
    
    def _init_state_transitions(self):
        """Инициализация таблицы переходов состояний."""
        for state in range(self.num_states):
            # Преобразуем состояние в список регистров
            registers = [(state >> i) & 1 for i in range(self.k - 2, -1, -1)]
            
            for inp in [0, 1]:
                # Текущее состояние + входной бит
                full_state = [inp] + registers
                
                # Вычисляем выходные биты
                out1 = 0
                out2 = 0
                for i in range(self.k):
                    if self.g1[i] == 1:
                        out1 ^= full_state[i]
                    if self.g2[i] == 1:
                        out2 ^= full_state[i]
                
                # Новое состояние (сдвиг)
                new_registers = [inp] + registers[:-1]
                new_state = 0
                for i, bit in enumerate(new_registers):
                    if bit:
                        new_state |= (1 << (self.k - 2 - i))
                
                self.next_states[(state, inp)] = (new_state, out1, out2)
    
    def hamming_distance(self, received, expected):
        """Расстояние Хэмминга для жесткого декодирования."""
        return sum(1 for r, e in zip(received, expected) if r != e)
    
    def euclidean_distance(self, received, expected):
        """Евклидово расстояние для мягкого декодирования."""
        # expected: (0,0) -> (-1,-1), (0,1) -> (-1,1), (1,0) -> (1,-1), (1,1) -> (1,1)
        exp_symbols = [2*e - 1 for e in expected]  # Преобразуем биты в уровни (-1 или 1)
        return sum((r - e)**2 for r, e in zip(received, exp_symbols))
    
    def decode_hard(self, received_bits):
        """
        Жесткое декодирование (вход - биты 0/1).
        """
        return self._viterbi(received_bits, hard_decision=True)
    
    def decode_soft(self, received_levels):
        """
        Мягкое декодирование (вход - уровни сигнала, например, 0.9, -0.1).
        """
        return self._viterbi(received_levels, hard_decision=False)
    
    def _viterbi(self, received, hard_decision=True):
        """
        Основной алгоритм Витерби.
        """
        # Инициализация
        num_steps = len(received) // 2
        # Таблица путей: для каждого состояния храним (метрика, путь)
        paths = {state: (float('inf'), []) for state in range(self.num_states)}
        paths[0] = (0, [])  # Начинаем с состояния 0
        
        for step in range(num_steps):
            # Получаем принятую пару битов для этого шага
            if hard_decision:
                # Для жесткого декодирования - просто биты
                rec_pair = (received[2*step], received[2*step + 1])
            else:
                # Для мягкого декодирования - уровни сигнала
                rec_pair = (received[2*step], received[2*step + 1])
            
            new_paths = {}
            
            # Для каждого текущего состояния
            for state, (metric, path) in paths.items():
                if metric == float('inf'):
                    continue
                
                # Пробуем оба возможных входных бита (0 и 1)
                for inp in [0, 1]:
                    next_state, out1, out2 = self.next_states[(state, inp)]
                    expected = (out1, out2)
                    
                    # Вычисляем метрику (расстояние)
                    if hard_decision:
                        branch_metric = self.hamming_distance(rec_pair, expected)
                    else:
                        branch_metric = self.euclidean_distance(rec_pair, expected)
                    
                    new_metric = metric + branch_metric
                    
                    # Обновляем путь
                    if next_state not in new_paths or new_metric < new_paths[next_state][0]:
                        new_paths[next_state] = (new_metric, path + [inp])
            
            paths = new_paths
        
        # Выбираем путь с наименьшей метрикой
        best_state = min(paths.keys(), key=lambda s: paths[s][0])
        best_path = paths[best_state][1]
        
        return best_path


# ==================== КЛАСС 3: КОД РИДА-СОЛОМОНА (ГРАФИЧЕСКИЙ) ====================

class ReedSolomonDemo:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        
        # Параметры линии
        self.a = 2
        self.b = 1
        
        # Точки
        self.data_points = []
        self.control_points = []
        self.received_points = []
        
        # Параметры для рисования
        self.canvas_width = 550
        self.canvas_height = 350
        self.margin = 40
        self.point_radius = 6
        
        self.create_widgets()
        self.generate_random_line()
    
    def create_widgets(self):
        # Верхняя панель с кнопками
        control_frame = ttk.Frame(self.parent)
        control_frame.pack(pady=5)
        
        ttk.Button(control_frame, text="Новая линия", command=self.generate_random_line).pack(side='left', padx=3)
        ttk.Button(control_frame, text="Внести ошибку", command=self.introduce_error).pack(side='left', padx=3)
        ttk.Button(control_frame, text="Исправить ошибку", command=self.correct_error).pack(side='left', padx=3)
        ttk.Button(control_frame, text="Сбросить", command=self.reset_points).pack(side='left', padx=3)
        
        # Холст для рисования
        self.canvas = tk.Canvas(self.parent, width=self.canvas_width, height=self.canvas_height, bg='white', highlightthickness=1, highlightbackground='gray')
        self.canvas.pack(pady=5)
        
        # Информационная панель
        self.info_label = ttk.Label(self.parent, text="", font=('Arial', 9))
        self.info_label.pack(pady=2)
        
        # Пояснительный текст
        explanation = """
            Принцип: Все точки лежат на одной прямой. Синие - данные, зеленые - контрольные.
            Красная точка - ошибка. При исправлении программа восстановит линию по 3 правильным точкам.
        """
        
        explanation_label = ttk.Label(self.parent, text=explanation, justify='left', font=('Arial', 8), wraplength=550)
        explanation_label.pack(pady=5)
    
    def generate_random_line(self):
        """Генерирует случайную линию"""
        self.a = random.randint(-3, 4)
        self.b = random.randint(-5, 6)
        
        # Генерируем 4 разные x координаты
        x_values = random.sample(range(-5, 6), 4)
        x_values.sort()
        
        self.data_points = []
        self.control_points = []
        
        for i, x in enumerate(x_values):
            y = self.a * x + self.b
            if i < 2:
                self.data_points.append((x, y))
            else:
                self.control_points.append((x, y))
        
        self.received_points = self.data_points + self.control_points
        self.update_display()
        self.info_label.config(text=f"Исходная линия: y = {self.a}x + {self.b}")
    
    def introduce_error(self):
        """Вносит ошибку в случайную точку"""
        if not self.received_points:
            return
        
        idx = random.randint(0, 3)
        x, y = self.received_points[idx]
        
        # Искажаем точку
        error = random.choice([-2, -1, 1, 2])
        new_y = y + error
        self.received_points[idx] = (x, new_y)
        
        self.update_display()
        point_type = "данных" if idx < 2 else "контрольная"
        self.info_label.config(text=f"Ошибка внесена в {point_type} точку (x={x})")
    
    def correct_error(self):
        """Исправляет ошибку, восстанавливая линию"""
        # Проверяем все комбинации по 3 точки
        for i in range(4):
            for j in range(i+1, 4):
                for k in range(j+1, 4):
                    points = [self.received_points[i], self.received_points[j], self.received_points[k]]
                    
                    # Проверяем, лежат ли точки на одной прямой
                    (x1, y1), (x2, y2), (x3, y3) = points
                    
                    # Проверка коллинеарности через определитель
                    collinear = abs((x2 - x1) * (y3 - y1) - (x3 - x1) * (y2 - y1)) < 0.0001
                    
                    if collinear and (x2 - x1) != 0:
                        # Восстанавливаем линию
                        a_line = (y2 - y1) / (x2 - x1)
                        b_line = y1 - a_line * x1
                        
                        # Восстанавливаем все точки
                        all_x = [p[0] for p in self.data_points + self.control_points]
                        self.received_points = [(x, a_line * x + b_line) for x in all_x]
                        
                        self.update_display()
                        self.info_label.config(text=f"Ошибка исправлена! Восстановлена линия: y = {a_line:.2f}x + {b_line:.2f}")
                        return
        
        self.info_label.config(text="Не удалось исправить ошибку - возможно несколько ошибок")
    
    def reset_points(self):
        """Сбрасывает к исходным точкам"""
        self.received_points = self.data_points + self.control_points
        self.update_display()
        self.info_label.config(text=f"Точки сброшены к исходным (y = {self.a}x + {self.b})")
    
    def update_display(self):
        """Обновляет отображение на холсте"""
        self.canvas.delete("all")
        
        if not self.received_points:
            return
        
        # Находим мин и макс для масштабирования
        all_x = [p[0] for p in self.received_points]
        all_y = [p[1] for p in self.received_points]
        
        x_min, x_max = min(all_x) - 1, max(all_x) + 1
        y_min, y_max = min(all_y) - 2, max(all_y) + 2
        
        # Функция для преобразования координат
        def to_canvas(x, y):
            canvas_x = self.margin + (x - x_min) * (self.canvas_width - 2*self.margin) / (x_max - x_min)
            canvas_y = self.canvas_height - self.margin - (y - y_min) * (self.canvas_height - 2*self.margin) / (y_max - y_min)
            return canvas_x, canvas_y
        
        # Рисуем сетку
        for i in range(int(x_min), int(x_max) + 1):
            x_canvas, _ = to_canvas(i, y_min)
            self.canvas.create_line(x_canvas, self.margin, x_canvas, self.canvas_height - self.margin, fill='#e0e0e0', width=1)
        
        for i in range(int(y_min), int(y_max) + 1):
            _, y_canvas = to_canvas(x_min, i)
            self.canvas.create_line(self.margin, y_canvas, self.canvas_width - self.margin, y_canvas, fill='#e0e0e0', width=1)
        
        # Рисуем исходную линию (пунктиром)
        x1_canvas, y1_canvas = to_canvas(x_min, self.a * x_min + self.b)
        x2_canvas, y2_canvas = to_canvas(x_max, self.a * x_max + self.b)
        self.canvas.create_line(x1_canvas, y1_canvas, x2_canvas, y2_canvas, fill='gray', dash=(5, 5), width=2)
        
        # Рисуем все полученные точки
        for i, (x, y) in enumerate(self.received_points):
            canvas_x, canvas_y = to_canvas(x, y)
            
            # Определяем цвет точки
            original_y = self.a * x + self.b
            is_error = abs(y - original_y) > 0.0001
            
            if is_error:
                color = 'red'
                outline = 'darkred'
            elif (x, y) in self.data_points:
                color = 'blue'
                outline = 'darkblue'
            else:
                color = 'green'
                outline = 'darkgreen'
            
            # Рисуем точку
            self.canvas.create_oval(canvas_x - self.point_radius, canvas_y - self.point_radius, canvas_x + self.point_radius, canvas_y + self.point_radius, fill=color, outline=outline, width=2)
            
            # Подпись координат
            self.canvas.create_text(canvas_x, canvas_y - self.point_radius - 8, text=f"({x},{y})", font=('Arial', 7))


# ==================== КЛАСС 4: LDPC КОД ====================

class LDPCDemo:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.create_widgets()
        self.run_demo()
    
    def create_widgets(self):
        # Текстовое поле для вывода
        self.text_area = scrolledtext.ScrolledText(self.parent, width=70, height=25, wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Кнопка для повторного запуска
        ttk.Button(self.parent, text="Запустить демонстрацию LDPC", command=self.run_demo).pack(pady=5)
    
    def run_demo(self):
        """Запускает демонстрацию LDPC и выводит результат в текстовое поле"""
        self.text_area.delete(1.0, tk.END)
        
        # Перенаправляем stdout в текстовое поле
        old_stdout = sys.stdout
        sys.stdout = TextRedirector(self.text_area)
        
        # Запускаем демонстрацию
        self.demonstrate_ldpc_concepts()
        
        # Восстанавливаем stdout
        sys.stdout = old_stdout
    
    def demonstrate_ldpc_concepts(self):
        """
        Упрощенная демонстрация основных концепций LDPC-кодов
        """
        
        print("=" * 60)
        print("ДЕМОНСТРАЦИЯ КОНЦЕПЦИЙ LDPC-КОДОВ")
        print("=" * 60)
        
        # Фиксируем seed для воспроизводимости
        random.seed(42)
        
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


# ==================== КЛАСС 5: СВЕРТОЧНЫЙ КОД (ГРАФИЧЕСКИЙ) ====================

class ConvolutionalDemo:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.coder = ConvolutionalCode()
        self.decoder = ViterbiDecoder()
        self.create_widgets()
        self.run_default_example()
    
    def create_widgets(self):
        # Верхняя панель
        control_frame = ttk.Frame(self.parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Входные биты:").pack(side=tk.LEFT, padx=5)
        self.input_entry = ttk.Entry(control_frame, width=20)
        self.input_entry.pack(side=tk.LEFT, padx=5)
        self.input_entry.insert(0, "111")
        
        ttk.Button(control_frame, text="Кодировать", command=self.run_encode).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Декодировать (жесткое)", command=self.run_decode_hard).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Декодировать (мягкое)", command=self.run_decode_soft).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Сброс", command=self.reset).pack(side=tk.LEFT, padx=5)
        
        # Основная область
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Левая часть - ввод/вывод
        left_frame = ttk.LabelFrame(main_frame, text="Результаты")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.text_area = scrolledtext.ScrolledText(left_frame, width=50, height=20, wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Правая часть - пояснения
        right_frame = ttk.LabelFrame(main_frame, text="Информация")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5)
        
        info_text = """
            СВЕРТОЧНЫЙ КОД NASA (r=1/2, k=7)

            Полиномы:
                • G1 = 1111001 (171 восьм.) - 1-й выход
                • G2 = 1011011 (133 восьм.) - 2-й выход

            Параметры:
                • Скорость кода: 1/2
                • Длина ограничения: 7
                • Состояний: 64

            Декодирование:
                • Жесткое - использует биты 0/1
                • Мягкое - использует уровни сигнала (например, 0.9, -0.1)

            Алгоритм: Витерби
        """
        
        ttk.Label(right_frame, text=info_text, justify=tk.LEFT, wraplength=200).pack(padx=5, pady=5)
        
        # Переменные для хранения данных
        self.original_bits = []
        self.encoded_bits = []
    
    def run_default_example(self):
        """Запускает пример по умолчанию"""
        self.original_bits = [1, 1, 1]
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, "111")
        self.run_encode()
    
    def run_encode(self):
        """Кодирует введенную последовательность"""
        input_text = self.input_entry.get().strip()
        if not input_text:
            return
        
        # Преобразуем строку в список битов
        self.original_bits = []
        for ch in input_text:
            if ch in '01':
                self.original_bits.append(int(ch))
        
        if not self.original_bits:
            messagebox.showerror("Ошибка", "Введите биты (0 и 1)")
            return
        
        # Кодируем
        self.coder.reset()
        self.encoded_bits = self.coder.encode_sequence(self.original_bits)
        
        # Выводим результат
        self.text_area.delete(1.0, tk.END)
        print(f"Исходное сообщение: {self.original_bits}", file=TextRedirector(self.text_area))
        print(f"Закодированная последовательность (с очисткой):", file=TextRedirector(self.text_area))
        print(f"{self.encoded_bits}", file=TextRedirector(self.text_area))
        print(f"\nДлина: {len(self.encoded_bits)} бит", file=TextRedirector(self.text_area))
    
    def run_decode_hard(self):
        """Жесткое декодирование"""
        if not self.encoded_bits:
            messagebox.showinfo("Инфо", "Сначала выполните кодирование")
            return
        
        self.text_area.insert(tk.END, "\n" + "-"*40 + "\n")
        print("ЖЕСТКОЕ ДЕКОДИРОВАНИЕ:", file=TextRedirector(self.text_area))
        
        # Декодируем
        decoded = self.decoder.decode_hard(self.encoded_bits)
        
        print(f"Декодировано: {decoded}", file=TextRedirector(self.text_area))
        print(f"Совпадает с исходным? {decoded == self.original_bits}", file=TextRedirector(self.text_area))
    
    def run_decode_soft(self):
        """Мягкое декодирование"""
        if not self.encoded_bits:
            messagebox.showinfo("Инфо", "Сначала выполните кодирование")
            return
        
        self.text_area.insert(tk.END, "\n" + "-"*40 + "\n")
        print("МЯГКОЕ ДЕКОДИРОВАНИЕ (с имитацией шума):", file=TextRedirector(self.text_area))
        
        # Преобразуем в уровни сигнала
        signal_levels = [1.0 if bit == 1 else -1.0 for bit in self.encoded_bits]
        
        # Добавляем небольшие искажения к первым двум битам для демонстрации
        noisy_signal = signal_levels.copy()
        if len(noisy_signal) >= 2:
            noisy_signal[0] = 0.9   # Вместо 1.0
            noisy_signal[1] = -0.1  # Вместо 1.0
        
        print(f"Исходный сигнал (первые 6): {[f'{v:.1f}' for v in signal_levels[:6]]}", file=TextRedirector(self.text_area))
        print(f"Принятый сигнал (первые 6): {[f'{v:.1f}' for v in noisy_signal[:6]]}", file=TextRedirector(self.text_area))
        
        # Мягкое декодирование
        decoded_soft = self.decoder.decode_soft(noisy_signal)
        print(f"\nРезультат мягкого декодирования: {decoded_soft}", file=TextRedirector(self.text_area))
        print(f"Совпадает с исходным? {decoded_soft == self.original_bits}", file=TextRedirector(self.text_area))
        
        # Для сравнения - жесткое
        hard_bits = [1 if level > 0 else 0 for level in noisy_signal]
        decoded_hard = self.decoder.decode_hard(hard_bits)
        print(f"\nДля сравнения - жесткое декодирование:", file=TextRedirector(self.text_area))
        print(f"Определенные биты: {hard_bits[:6]}...", file=TextRedirector(self.text_area))
        print(f"Результат: {decoded_hard}", file=TextRedirector(self.text_area))
    
    def reset(self):
        """Сброс"""
        self.coder.reset()
        self.text_area.delete(1.0, tk.END)
        self.run_default_example()


# ==================== КЛАСС 6: КОД ХЭММИНГА (ГРАФИЧЕСКИЙ) ====================

class HammingDemo:
    def __init__(self, parent_frame):
        self.parent = parent_frame
        self.hamming = HammingCode()
        self.create_widgets()
        self.run_default_example()
    
    def create_widgets(self):
        # Верхняя панель
        control_frame = ttk.Frame(self.parent)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="4 бита данных:").pack(side=tk.LEFT, padx=5)
        self.input_entry = ttk.Entry(control_frame, width=10)
        self.input_entry.pack(side=tk.LEFT, padx=5)
        self.input_entry.insert(0, "0001")
        
        ttk.Button(control_frame, text="Кодировать", command=self.run_encode).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Внести ошибку", command=self.introduce_error).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Декодировать", command=self.run_decode).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Сброс", command=self.reset).pack(side=tk.LEFT, padx=5)
        
        # Основная область
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Левая часть - результаты
        left_frame = ttk.LabelFrame(main_frame, text="Результаты")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.text_area = scrolledtext.ScrolledText(left_frame, width=50, height=20, wrap=tk.WORD)
        self.text_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Правая часть - таблица синдромов
        right_frame = ttk.LabelFrame(main_frame, text="Таблица синдромов")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, padx=5)
        
        syndrome_text = """
            Синдром -> Позиция ошибки:
            [0,0,0] -> нет ошибки
            [1,0,0] -> позиция 1
            [0,1,0] -> позиция 2
            [1,1,0] -> позиция 3
            [0,0,1] -> позиция 4
            [1,0,1] -> позиция 5
            [0,1,1] -> позиция 6
            [1,1,1] -> позиция 7
        """
        
        ttk.Label(right_frame, text=syndrome_text, justify=tk.LEFT, font=('Courier', 9)).pack(padx=5, pady=5)
        
        # Переменные для хранения данных
        self.original_data = []
        self.codeword = []
        self.received = []
    
    def run_default_example(self):
        """Запускает пример по умолчанию"""
        self.original_data = [0, 0, 0, 1]
        self.input_entry.delete(0, tk.END)
        self.input_entry.insert(0, "0001")
        self.run_encode()
    
    def parse_input(self):
        """Парсит введенные биты"""
        input_text = self.input_entry.get().strip()
        bits = []
        for ch in input_text:
            if ch in '01':
                bits.append(int(ch))
        
        if len(bits) != 4:
            messagebox.showerror("Ошибка", "Введите ровно 4 бита (0 и 1)")
            return None
        
        return bits
    
    def run_encode(self):
        """Кодирует введенные данные"""
        bits = self.parse_input()
        if bits is None:
            return
        
        self.original_data = bits
        self.codeword = self.hamming.encode(bits)
        self.received = self.codeword.copy()
        
        self.text_area.delete(1.0, tk.END)
        print(f"Исходные данные: {self.original_data}", file=TextRedirector(self.text_area))
        print(f"Кодовое слово:   {self.codeword}", file=TextRedirector(self.text_area))
        print(f"\nПроверочные биты: {self.codeword[4:]}", file=TextRedirector(self.text_area))
    
    def introduce_error(self):
        """Вносит ошибку в кодовое слово"""
        if not self.codeword:
            messagebox.showinfo("Инфо", "Сначала выполните кодирование")
            return
        
        # Выбираем случайную позицию для ошибки
        error_pos = random.randint(0, 6)
        self.received = self.codeword.copy()
        self.received[error_pos] ^= 1
        
        self.text_area.insert(tk.END, "\n" + "-"*40 + "\n")
        print(f"ВНЕСЕНА ОШИБКА в позиции {error_pos+1}", file=TextRedirector(self.text_area))
        print(f"Искаженное слово: {self.received}", file=TextRedirector(self.text_area))
    
    def run_decode(self):
        """Декодирует принятое слово"""
        if not self.received:
            messagebox.showinfo("Инфо", "Нет данных для декодирования")
            return
        
        data, corrected, syndrome, err_pos, fixed = self.hamming.decode(self.received)
        
        self.text_area.insert(tk.END, "\n" + "="*50 + "\n")
        print("ДЕКОДИРОВАНИЕ:", file=TextRedirector(self.text_area))
        print(f"Принятое слово:   {self.received}", file=TextRedirector(self.text_area))
        print(f"Синдром:          {syndrome} -> позиция ошибки: {err_pos}", file=TextRedirector(self.text_area))
        
        if fixed:
            print(f"Исправленное слово: {corrected}", file=TextRedirector(self.text_area))
            print(f"Декодированные данные: {data}", file=TextRedirector(self.text_area))
            print("✓ Ошибка успешно исправлена!", file=TextRedirector(self.text_area))
        else:
            if err_pos == 0:
                print("✓ Ошибок не обнаружено", file=TextRedirector(self.text_area))
            else:
                print("❌ Обнаружена ошибка, но позиция вне диапазона", file=TextRedirector(self.text_area))
        
        print(f"\nСовпадает с исходным? {data == self.original_data}", file=TextRedirector(self.text_area))
    
    def reset(self):
        """Сброс"""
        self.run_encode()


# ==================== КЛАСС ДЛЯ ПЕРЕХВАТА ВЫВОДА ====================

class TextRedirector:
    """Класс для перенаправления stdout в текстовое поле"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
    
    def write(self, string):
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
    
    def flush(self):
        pass


# ==================== ГЛАВНОЕ ПРИЛОЖЕНИЕ ====================

class UnifiedCodingApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Единая программа демонстрации помехоустойчивых кодов")
        self.root.geometry("900x700")
        
        # Устанавливаем иконку (если есть)
        try:
            self.root.iconbitmap(default='icon.ico')
        except:
            pass
        
        # Создаем меню
        self.create_menu()
        
        # Создаем главный контейнер с вкладками
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Создаем вкладки для каждого кода
        self.create_tabs()
        
        # Статус бар
        self.status_bar = ttk.Label(root, text="Готов к работе", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Привязываем событие смены вкладки
        self.notebook.bind('<<NotebookTabChanged>>', self.on_tab_change)
    
    def create_menu(self):
        """Создает главное меню"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Меню Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Выход", command=self.root.quit, accelerator="Ctrl+Q")
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        
        # Меню Справка
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self.show_about)
        help_menu.add_command(label="Инструкция", command=self.show_help)
    
    def create_tabs(self):
        """Создает вкладки для каждого кода"""
        # Вкладка 1: Код Хэмминга
        self.hamming_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.hamming_frame, text="Код Хэмминга (7,4)")
        self.hamming_demo = HammingDemo(self.hamming_frame)
        
        # Вкладка 2: Сверточный код
        self.conv_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.conv_frame, text="Сверточный код NASA")
        self.conv_demo = ConvolutionalDemo(self.conv_frame)
        
        # Вкладка 3: Код Рида-Соломона (графический)
        self.rs_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rs_frame, text="Код Рида-Соломона")
        self.rs_demo = ReedSolomonDemo(self.rs_frame)
        
        # Вкладка 4: LDPC код
        self.ldpc_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ldpc_frame, text="LDPC код")
        self.ldpc_demo = LDPCDemo(self.ldpc_frame)
        
        # Вкладка 5: Сравнение кодов
        self.compare_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.compare_frame, text="Сравнение кодов")
        self.create_comparison_tab()
    
    def create_comparison_tab(self):
        """Создает вкладку сравнения кодов"""
        # Текст с описанием
        text_widget = scrolledtext.ScrolledText(self.compare_frame, wrap=tk.WORD, font=('Arial', 10))
        text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        comparison_text = """
            СРАВНЕНИЕ ПОМЕХОУСТОЙЧИВЫХ КОДОВ
            =================================

            1. КОД ХЭММИНГА (7,4)
                • Тип: Блочный линейный код
                • Длина: 7 бит, данных: 4 бита
                • Скорость: 4/7 ≈ 0.57
                • Минимальное расстояние: d_min = 3
                • Обнаруживает: до 2 ошибок
                • Исправляет: 1 ошибку
                • Применение: Память компьютеров, простые каналы связи
                • Преимущества: Простота реализации, быстрое декодирование
                • Недостатки: Низкая скорость, исправляет только 1 ошибку

            2. СВЕРТОЧНЫЙ КОД NASA (r=1/2, k=7)
                • Тип: Сверточный код
                • Скорость: 1/2
                • Длина ограничения: 7
                • Алгоритм декодирования: Витерби
                • Обнаруживает: Зависит от свободного расстояния
                • Исправляет: Множественные ошибки
                • Применение: Спутниковая связь, глубокий космос
                • Преимущества: Высокая эффективность, мягкое декодирование
                • Недостатки: Сложность декодирования растет с длиной ограничения

            3. КОД РИДА-СОЛОМОНА
                • Тип: Небинарный блочный код
                • Работает с символами (не битами)
                • Параметры: (n, k) над GF(2^m)
                • Минимальное расстояние: d_min = n - k + 1
                • Исправляет: (n - k)/2 ошибок в символах
                • Применение: CD/DVD, QR-коды, глубокий космос
                • Преимущества: Исправляет пакеты ошибок
                • Недостатки: Высокая сложность для больших блоков

            4. LDPC КОД (Low-Density Parity-Check)
                • Тип: Линейный блочный код с разреженной матрицей
                • Скорость: Гибкая (зависит от матрицы)
                • Декодирование: Итеративное (вероятностное)
                • Применение: Wi-Fi, Ethernet, DVB, 5G
                • Преимущества: Близки к пропускной способности канала
                • Недостатки: Высокая вычислительная сложность

            ОБЩЕЕ СРАВНЕНИЕ:
            ─────────────────────────────────────────────────────
            Параметр          | Хэмминг | Сверточный | Рид-Соломон | LDPC
            ─────────────────────────────────────────────────────
            Скорость кода     | 0.57    | 0.5        | Гибкая      | Гибкая
            Коррекция ошибок  | 1 бит   | Много      | Много симв. | Много бит
            Сложность         | Низкая  | Средняя    | Высокая     | Очень выс.
            Применение        | Простое | Космос     | Хранение    | Соврем. сети
            ─────────────────────────────────────────────────────

            ВЫБОР КОДА зависит от:
                • Характера ошибок (одиночные/пакетные)
                • Требуемой скорости передачи
                • Допустимой сложности реализации
                • Типа канала связи
        """
        
        text_widget.insert(tk.END, comparison_text)
        text_widget.config(state=tk.DISABLED)
    
    def on_tab_change(self, event):
        """Обработчик смены вкладки"""
        tab_id = self.notebook.select()
        tab_text = self.notebook.tab(tab_id, "text")
        self.status_bar.config(text=f"Текущий код: {tab_text}")
    
    def show_about(self):
        """Показывает информацию о программе"""
        about_text = """
            Единая программа демонстрации помехоустойчивых кодов
            Версия 1.0

            Разработчик: Учебная программа
            Дата: 2026

            Включает реализации:
                • Код Хэмминга (7,4)
                • Сверточный код NASA
                • Код Рида-Соломона
                • LDPC код

            Для образовательных целей
        """
        messagebox.showinfo("О программе", about_text)
    
    def show_help(self):
        """Показывает справку"""
        help_text = """
            ИНСТРУКЦИЯ ПО ИСПОЛЬЗОВАНИЮ

            1. Код Хэмминга:
                - Введите 4 бита данных (только 0 и 1)
                - Нажмите "Кодировать" для получения кодового слова
                - "Внести ошибку" - искажает один бит
                - "Декодировать" - исправляет ошибку

            2. Сверточный код:
                - Введите последовательность битов (например, 111)
                - "Кодировать" - получаете закодированную последовательность
                - "Декодировать (жесткое)" - использует биты
                - "Декодировать (мягкое)" - использует уровни сигнала

            3. Код Рида-Соломона:
                - Наглядная демонстрация на точках
                - Красная точка - ошибка
                - "Исправить ошибку" - восстановит линию

            4. LDPC код:
                - Текстовая демонстрация принципов работы
                - Показывает разреженную матрицу и проверку четности

            5. Сравнение кодов:
                - Таблица с характеристиками всех кодов
        """
        messagebox.showinfo("Справка", help_text)


# ==================== ЗАПУСК ПРОГРАММЫ ====================

def main():
    root = tk.Tk()
    app = UnifiedCodingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()