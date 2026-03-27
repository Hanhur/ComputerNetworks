import tkinter as tk
from tkinter import ttk
import random
import math

class ReedSolomonDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("Демонстрация принципа работы кода Рида-Соломона")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Параметры линии
        self.a = 2
        self.b = 1
        
        # Точки
        self.data_points = []
        self.control_points = []
        self.received_points = []
        
        # Параметры для рисования
        self.canvas_width = 600
        self.canvas_height = 400
        self.margin = 50
        self.point_radius = 8
        
        self.create_widgets()
        self.generate_random_line()
    
    def create_widgets(self):
        # Верхняя панель с кнопками
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)
        
        ttk.Button(control_frame, text="Новая линия", command=self.generate_random_line).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Внести ошибку", command=self.introduce_error).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Исправить ошибку", command=self.correct_error).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Сбросить", command=self.reset_points).pack(side='left', padx=5)
        
        # Холст для рисования
        self.canvas = tk.Canvas(self.root, width=self.canvas_width, height=self.canvas_height, bg='white')
        self.canvas.pack(pady=10)
        
        # Информационная панель
        self.info_label = ttk.Label(self.root, text="", font=('Arial', 10))
        self.info_label.pack(pady=5)
        
        # Пояснительный текст
        explanation = """Как это работает:
        • Синие точки - информационные (данные)
        • Зеленые точки - контрольные (избыточность)
        • Все точки лежат на одной прямой
        • Красная точка - ошибка при передаче
        • При нажатии "Исправить ошибку" программа восстановит линию по 3 правильным точкам"""
        
        explanation_label = ttk.Label(self.root, text=explanation, justify='left', font=('Arial', 9))
        explanation_label.pack(pady=10)
    
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
            self.canvas.create_text(canvas_x, canvas_y - self.point_radius - 10, text=f"({x},{y})", font=('Arial', 8))

def main():
    root = tk.Tk()
    app = ReedSolomonDemo(root)
    root.mainloop()

if __name__ == "__main__":
    main()