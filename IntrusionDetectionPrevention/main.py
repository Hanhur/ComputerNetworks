"""
Моделирование систем обнаружения и предотвращения вторжений (IDS/IPS)
на основе текста о сетевой безопасности.
"""

import random
from dataclasses import dataclass
from typing import List, Tuple, Dict
from collections import deque


# ============================================================
# 1. Моделирование сетевых пакетов и атак
# ============================================================

@dataclass
class Packet:
    """Модель сетевого пакета."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: bytes
    ttl: int = 64


class AttackSignature:
    """Сигнатура известной атаки (байтовый паттерн)."""
    
    def __init__(self, name: str, pattern: bytes, dst_port: int = None):
        self.name = name
        self.pattern = pattern
        self.dst_port = dst_port
    
    def matches(self, packet: Packet) -> bool:
        """Проверяет, соответствует ли пакет сигнатуре."""
        if self.dst_port and packet.dst_port != self.dst_port:
            return False
        return self.pattern in packet.payload


# ============================================================
# 2. Сигнатурная IDS
# ============================================================

class SignatureIDS:
    """Сигнатурная система обнаружения вторжений."""
    
    def __init__(self):
        self.signatures: List[AttackSignature] = []
        self.alerts = []
    
    def add_signature(self, signature: AttackSignature):
        self.signatures.append(signature)
    
    def analyze_packet(self, packet: Packet) -> List[str]:
        """Анализирует пакет и возвращает список обнаруженных атак."""
        detected = []
        for sig in self.signatures:
            if sig.matches(packet):
                alert = f"[IDS] Обнаружена атака: {sig.name} от {packet.src_ip}"
                self.alerts.append(alert)
                detected.append(sig.name)
        return detected


# ============================================================
# 3. Аномалийная IDS (на основе скользящего среднего)
# ============================================================

class AnomalyIDS:
    """Система обнаружения аномалий на основе статистики трафика."""
    
    def __init__(self, window_size: int = 10, threshold: float = 2.0):
        self.window_size = window_size
        self.threshold = threshold
        self.history = deque(maxlen = window_size)
        self.alerts = []
    
    def _update_history(self, value: float):
        self.history.append(value)
    
    def _get_mean_std(self) -> Tuple[float, float]:
        if len(self.history) < 3:
            return 0.0, 1.0
        mean = sum(self.history) / len(self.history)
        variance = sum((x - mean) ** 2 for x in self.history) / len(self.history)
        std = variance ** 0.5
        return mean, max(std, 0.01)
    
    def analyze_packet_rate(self, current_rate: float) -> bool:
        """
        Анализирует текущую скорость пакетов.
        Возвращает True, если обнаружена аномалия.
        """
        self._update_history(current_rate)
        mean, std = self._get_mean_std()
        z_score = abs(current_rate - mean) / std
        
        if z_score > self.threshold:
            alert = f"[Anomaly] Необычная скорость трафика: {current_rate:.2f} пак/с (z = {z_score:.2f})"
            self.alerts.append(alert)
            return True
        return False


# ============================================================
# 4. IPS (Intrusion Prevention System)
# ============================================================

class IPS:
    """Система предотвращения вторжений — блокирует вредоносные пакеты."""
    
    def __init__(self, ids: SignatureIDS):
        self.ids = ids
        self.blocked_packets = 0
    
    def process_packet(self, packet: Packet) -> bool:
        """
        Обрабатывает пакет. Возвращает True, если пакет разрешён,
        False — если заблокирован.
        """
        detected = self.ids.analyze_packet(packet)
        if detected:
            print(f"[IPS] БЛОКИРУЮ пакет от {packet.src_ip}: {detected}")
            self.blocked_packets += 1
            return False
        return True


# ============================================================
# 5. Расчёт метрик качества (TP, FP, FN, TN)
# ============================================================

class MetricsCalculator:
    """Расчёт метрик точности, полноты, F-меры и accuracy."""
    
    def __init__(self):
        self.TP = 0  # True Positive: атака есть, сигнал есть
        self.FP = 0  # False Positive: атаки нет, сигнал есть
        self.FN = 0  # False Negative: атака есть, сигнала нет
        self.TN = 0  # True Negative: атаки нет, сигнала нет
    
    def update(self, attack_present: bool, alert_raised: bool):
        if attack_present and alert_raised:
            self.TP += 1
        elif not attack_present and alert_raised:
            self.FP += 1
        elif attack_present and not alert_raised:
            self.FN += 1
        elif not attack_present and not alert_raised:
            self.TN += 1
    
    @property
    def precision(self) -> float:
        """Точность: доля оправданных сигналов."""
        if self.TP + self.FP == 0:
            return 0.0
        return self.TP / (self.TP + self.FP)
    
    @property
    def recall(self) -> float:
        """Полнота: доля найденных атак."""
        if self.TP + self.FN == 0:
            return 0.0
        return self.TP / (self.TP + self.FN)
    
    @property
    def f_measure(self) -> float:
        """F-мера: гармоническое среднее точности и полноты."""
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)
    
    @property
    def accuracy(self) -> float:
        """Доля верных результатов."""
        total = self.TP + self.FP + self.FN + self.TN
        if total == 0:
            return 0.0
        return (self.TP + self.TN) / total
    
    def summary(self) -> str:
        return f"""
=== Метрики IDS ===
TP (верно обнаружено): {self.TP}
FP (ложная тревога):   {self.FP}
FN (пропущено атак):   {self.FN}
TN (верно пропущено):  {self.TN}
--------------------
Точность (Precision):  {self.precision:.3f}
Полнота   (Recall):    {self.recall:.3f}
F-мера:               {self.f_measure:.3f}
Accuracy:             {self.accuracy:.3f}
"""


# ============================================================
# 6. Ошибка базовой ставки (медицинский тест из текста)
# ============================================================

def base_rate_fallacy_demo():
    """
    Демонстрация ошибки базовой оценки из текста.
    Рассчитывает вероятность реальной атаки при срабатывании IDS.
    """
    print("\n" + "=" * 60)
    print("ДЕМОНСТРАЦИЯ ОШИБКИ БАЗОВОЙ ОЦЕНКИ (BASE RATE FALLACY)")
    print("=" * 60)
    
    # Параметры из текста про болезнь (атаку)
    P_S = 0.00001      # Базовая вероятность атаки = 1 на 100 000
    P_Pos_S = 0.99     # Чувствительность: 99% атак обнаруживается
    P_Neg_H = 0.99     # Специфичность: 99% нормального трафика без тревоги
    
    # Вычисляем P(Pos) — общую вероятность сигнала тревоги
    P_H = 1 - P_S
    P_Pos_H = 1 - P_Neg_H  # = 0.01 — ложные срабатывания
    
    P_Pos = P_S * P_Pos_S + P_H * P_Pos_H
    
    # Формула Байеса: P(S | Pos)
    P_S_Pos = (P_S * P_Pos_S) / P_Pos
    
    print(f"\nИсходные данные (как в тексте про болезнь):")
    print(f"  Вероятность атаки (базовая):       P(атака) = {P_S:.5f} (1 на 100 000)")
    print(f"  Чувствительность IDS:              P(сигнал|атака) = {P_Pos_S}")
    print(f"  Специфичность IDS:                 P(нет сигнала|нет атаки) = {P_Neg_H}")
    print(f"  → Вероятность ложной тревоги:      P(сигнал|нет атаки) = {P_Pos_H}")
    
    print(f"\nРезультат по формуле Байеса:")
    print(f"  P(атака | сигнал тревоги) = {P_S_Pos:.5f} = {P_S_Pos * 100:.4f}%")
    
    if P_S_Pos < 0.01:
        print("\n👉 ВЫВОД: Даже при срабатывании IDS вероятность реальной атаки < 1%!")
        print("   Именно поэтому важно минимизировать долю ложных срабатываний (False Positives).")
    else:
        print("   Ситуация лучше — но обычно на практике атаки ещё более редки.")
    
    return P_S_Pos


# ============================================================
# 7. Симуляция методов обхода IDS (TTL, фрагментация)
# ============================================================

def ids_evasion_demo():
    """Демонстрирует проблему обхода IDS с помощью TTL и перекрывающихся сегментов."""
    print("\n" + "=" * 60)
    print("МЕТОДЫ ОБХОДА IDS (IDS EVASION)")
    print("=" * 60)
    
    # Пакет с малым TTL
    packet_ttl1 = Packet("10.0.0.1", "10.0.0.2", 12345, 80, b"GET /admin HTTP/1.1", ttl = 1)
    packet_ttl64 = Packet("10.0.0.1", "10.0.0.2", 12345, 80, b"GET /admin HTTP/1.1", ttl = 64)
    
    print("\n[Проблема TTL]")
    print(f"  Пакет с TTL = 1: может не достичь цели, но IDS его видит.")
    print(f"  Пакет с TTL = 64: нормально достигает.")
    print("  Если атакующий шлёт вредоносный пакет с TTL = 1, а IDS видит его, а хост — нет,")
    print("  то IDS может ложно сработать или, наоборот, пропустить атаку.")
    
    print("\n[Проблема перекрывающихся TCP-сегментов]")
    print("  Пакет A: байты 1-200, payload 'AAAA...'")
    print("  Пакет B: байты 100-300, payload 'BBBB...'")
    print("  Разные ОС по-разному собирают такие сегменты (Windows, Linux, BSD — по-разному).")
    print("  Если IDS собирает поток не так, как целевой хост — атака пройдёт.")
    
    print("\n👉 Вывод: NIDS сложнее защитить от обхода, чем HIDS.")


# ============================================================
# 8. Полная симуляция работы IDS/IPS
# ============================================================

def run_ids_simulation():
    """Запускает симуляцию: генерация трафика, обнаружение атак, расчёт метрик."""
    print("\n" + "=" * 60)
    print("СИМУЛЯЦИЯ РАБОТЫ SIGNATURE-BASED IDS")
    print("=" * 60)
    
    # Создаём IDS и добавляем сигнатуры
    ids = SignatureIDS()
    
    # Сигнатура эксплойта Hajime (условно)
    hajime_sig = AttackSignature("Hajime", b"\x48\x61\x6a\x69\x6d\x65", dst_port = 80)
    # Сигнатура сканирования портов (условно — пакет с портом 54321)
    port_scan_sig = AttackSignature("PortScan", b"\xDE\xAD\xBE\xEF", dst_port = 54321)
    
    ids.add_signature(hajime_sig)
    ids.add_signature(port_scan_sig)
    
    # Создаём IPS на основе этой IDS
    ips = IPS(ids)
    
    # Счётчик метрик
    metrics = MetricsCalculator()
    
    # Генерируем тестовый трафик
    test_packets = [
        # Нормальные пакеты
        Packet("192.168.1.10", "10.0.0.5", 45678, 80, b"GET /index.html HTTP/1.1", ttl = 64),
        Packet("192.168.1.11", "10.0.0.5", 45679, 443, b"....", ttl = 64),
        
        # Вредоносный пакет с Hajime
        Packet("5.5.5.5", "10.0.0.5", 12345, 80, b"AAAA\x48\x61\x6a\x69\x6d\x65BBBB", ttl = 64),
        
        # Нормальный пакет
        Packet("192.168.1.12", "10.0.0.5", 45680, 22, b"SSH_MSG", ttl = 64),
        
        # Сканирование портов
        Packet("8.8.8.8", "10.0.0.5", 9999, 54321, b"\xDE\xAD\xBE\xEF", ttl = 64),
        
        # Ещё нормальный
        Packet("192.168.1.13", "10.0.0.5", 45681, 80, b"POST /form HTTP/1.1", ttl = 64),
    ]
    
    # Для каждого пакета знаем, является ли он атакой (ground truth)
    # 0 = норма, 1 = атака
    ground_truth = [0, 0, 1, 0, 1, 0]
    
    print("\nОбработка пакетов IPS:")
    print("-" * 40)
    
    for i, packet in enumerate(test_packets):
        is_attack = (ground_truth[i] == 1)
        allowed = ips.process_packet(packet)
        
        # Сигнал тревоги: если IPS заблокировал (или IDS выдала бы алерт)
        # В нашей модели сигнал = обнаружение сигнатуры
        detected = len(ids.analyze_packet(packet)) > 0
        alert_raised = detected
        
        metrics.update(is_attack, alert_raised)
        
        status = "РАЗРЕШЁН" if allowed else "ЗАБЛОКИРОВАН"
        print(f"Пакет {i + 1}: {status} | Атака: {is_attack} | Сигнал: {alert_raised}")
    
    print(metrics.summary())
    
    print("👉 Интерпретация:")
    print("  - Precision: насколько мы уверены в сигналах тревоги")
    print("  - Recall:    сколько атак мы нашли")
    print("  - F-мера:    баланс между точностью и полнотой")
    print("  - Чем выше F-мера, тем лучше качество IDS.")


# ============================================================
# 9. Аномалийная IDS — симуляция
# ============================================================

def run_anomaly_demo():
    """Демонстрация работы аномалийной IDS."""
    print("\n" + "=" * 60)
    print("СИМУЛЯЦИЯ АНОМАЛИЙНОЙ IDS")
    print("=" * 60)
    
    anomaly_ids = AnomalyIDS(window_size = 5, threshold = 1.5)
    
    # Нормальный трафик: скорость ~10 пак/с
    normal_rates = [10, 11, 9, 10, 12, 10, 11, 9, 10, 11]
    # Аномалия: резкий скачок до 50
    traffic_rates = normal_rates + [50, 52, 48] + normal_rates[-5:]
    
    print("\nАнализ скорости трафика:")
    print("Время\tСкорость\tАномалия?")
    for t, rate in enumerate(traffic_rates):
        is_anomaly = anomaly_ids.analyze_packet_rate(rate)
        marker = "⚠️ ДА" if is_anomaly else "   нет"
        print(f"{t:3d}\t{rate:6.2f}\t{marker}")
    
    if anomaly_ids.alerts:
        print("\nСгенерированные оповещения:")
        for alert in anomaly_ids.alerts:
            print(f"  {alert}")
    
    print("\n👉 Аномалийные IDS могут найти новые атаки, но дают много ложных срабатываний.")


# ============================================================
# 10. Главная функция
# ============================================================

def main():
    """Запускает все демонстрации."""
    print("\n" + "=" * 70)
    print("МОДЕЛИРОВАНИЕ IDS/IPS НА ОСНОВЕ ТЕКСТА ОБ ОБНАРУЖЕНИИ ВТОРЖЕНИЙ")
    print("=" * 70)
    
    # 1. Симуляция работы сигнатурной IDS/IPS с метриками
    run_ids_simulation()
    
    # 2. Ошибка базовой ставки
    base_rate_fallacy_demo()
    
    # 3. Методы обхода IDS
    ids_evasion_demo()
    
    # 4. Аномалийная IDS
    run_anomaly_demo()
    
    print("\n" + "=" * 70)
    print("ИТОГОВЫЕ ВЫВОДЫ (из текста):")
    print("=" * 70)
    print(""" 
    1. Сигнатурные IDS точны, но не видят новые атаки.
    2. Аномалийные IDS находят новое, но шумят (много False Positives).
    3. IPS блокирует атаки, но снижает производительность и риск ошибок.
    4. Ошибка базовой ставки: даже при 99% точности, редкие атаки дают <1% вероятности реальной угрозы при срабатывании сигнала.
    5. NIDS уязвимы для обхода (TTL, фрагментация, перекрытие сегментов).
    6. Лучшая защита — эшелонированная (Firewall + IDS + IPS + HIDS).
    """)


if __name__ == "__main__":
    main()