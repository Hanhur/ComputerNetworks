"""
Учебная симуляция предсказуемости TCP ISN и атаки подмены соединения (connection spoofing)
Основано на описании атаки Кевина Митника на Суперкомпьютерный центр Сан-Диего (1994)

ВНИМАНИЕ: Это ТОЛЬКО для образовательных целей в изолированной среде.
Реальная реализация требует raw sockets, требует прав root и незаконна без разрешения.
"""

import time
import random
from dataclasses import dataclass
from typing import List, Optional


class PredictableISNGenerator:
    """
    Эмуляция предсказуемого генератора ISN (как в старых TCP-стеках до 1994 года)
    В реальности использовался предсказуемый инкремент, часто основанный на времени
    """
    def __init__(self, seed: int = None):
        self.last_isn = seed if seed is not None else random.randint(1000, 5000)
        self.increment = 64000  # типичный фиксированный инкремент в старых системах
        
    def get_next_isn(self) -> int:
        """Генерирует следующий ISN предсказуемым образом"""
        self.last_isn += self.increment
        return self.last_isn
    
    def get_isn_at_time(self, time_delta_ms: int) -> int:
        """ISN на основе времени (ещё более предсказуемый метод)"""
        return self.last_isn + (time_delta_ms * 80)  # 80 - пример инкремента в миллисекунду


class ModernSecureISNGenerator:
    """
    Современный безопасный генератор ISN (RFC 6528) - для сравнения
    """
    def __init__(self):
        self.state = random.getrandbits(32)
        
    def get_next_isn(self) -> int:
        """ISN, который невозможно предсказать"""
        # Симуляция криптостойкого псевдослучайного генератора
        self.state = (self.state * 1103515245 + 12345) & 0xFFFFFFFF
        return self.state


class TCPSessionSimulator:
    """Симулятор TCP-соединения для демонстрации атаки"""
    
    @dataclass
    class TCPPacket:
        seq: int
        ack: int
        flags: str
        data: str = ""
    
    def __init__(self, name: str, isn_generator):
        self.name = name
        self.isn_gen = isn_generator
        self.last_seq = 0
        self.last_ack = 0
        self.connection_state = "CLOSED"
        
    def send_syn(self, dst_seq: int = None) -> TCPPacket:
        """Отправка SYN пакета"""
        isn = self.isn_gen.get_next_isn()
        self.last_seq = isn
        self.connection_state = "SYN_SENT"
        print(f"[{self.name}] → Отправка SYN (ISN={isn})")
        return self.TCPPacket(seq = isn, ack = 0, flags = "SYN")
    
    def send_syn_ack(self, remote_seq: int) -> TCPPacket:
        """Отправка SYN-ACK в ответ на SYN"""
        isn = self.isn_gen.get_next_isn()
        self.last_seq = isn
        self.last_ack = remote_seq + 1
        self.connection_state = "SYN_RCVD"
        print(f"[{self.name}] → Отправка SYN/ACK (SEQ={isn}, ACK={remote_seq+1})")
        return self.TCPPacket(seq = isn, ack = remote_seq + 1, flags = "SYN_ACK")
    
    def send_ack(self, remote_seq: int) -> TCPPacket:
        """Отправка ACK"""
        self.last_ack = remote_seq + 1
        print(f"[{self.name}] → Отправка ACK (SEQ={self.last_seq}, ACK={remote_seq+1})")
        return self.TCPPacket(seq = self.last_seq, ack = remote_seq + 1, flags = "ACK")
    
    def send_data(self, data: str, remote_seq: int) -> TCPPacket:
        """Отправка данных"""
        seq = self.last_seq
        ack = remote_seq + 1
        self.last_seq += len(data)
        print(f"[{self.name}] → Отправка данных: '{data}' (SEQ={seq}, ACK={ack})")
        return self.TCPPacket(seq = seq, ack = ack, flags = "PSH_ACK", data = data)
    
    def send_rst(self) -> TCPPacket:
        """Отправка RST для сброса соединения"""
        print(f"[{self.name}] → Отправка RST (сброс соединения)")
        self.connection_state = "CLOSED"
        return self.TCPPacket(seq = self.last_seq, ack = 0, flags = "RST")


class MitnickAttackSimulator:
    """
    Симуляция атаки Митника:
    1. Наблюдение за ISN целевого хоста
    2. DoS на доверенный сервер (чтобы он не послал RST)
    3. Поддельный SYN с IP доверенного сервера
    4. Предсказание ISN ответа SYN/ACK
    5. Завершение рукопожатия и внедрение команды
    """
    
    def __init__(self):
        print("\n" + "=" * 70)
        print("СИМУЛЯЦИЯ TCP CONNECTION SPOOFING (Атака Митника, 1994)")
        print("=" * 70)
        
    def simulate_attack(self):
        # Шаг 0: Инициализация
        print("\n[Фаза 1] Инициализация:")
        print("Цель: X-терминал (target)")
        print("Доверенный сервер: trusted_server")
        print("Злоумышленник: attacker")
        
        # Предсказуемый генератор ISN (старая система)
        target_isn_gen = PredictableISNGenerator(seed = 5000)
        trusted_isn_gen = PredictableISNGenerator(seed = 10000)
        
        target = TCPSessionSimulator("X-терминал", target_isn_gen)
        trusted = TCPSessionSimulator("Сервер", trusted_isn_gen)
        
        # Фаза 1: Наблюдение за ISN цели
        print("\n[Фаза 2] Разведка — получение последовательности ISN от цели:")
        observed_isns = []
        for i in range(5):
            syn_packet = target.send_syn()
            observed_isns.append(syn_packet.seq)
            # Эмуляция ответа сброса (соединение не устанавливается)
            target.send_rst()
            time.sleep(0.1)
        
        print(f"\nНаблюдённые ISN: {observed_isns}")
        
        # Предсказание следующего ISN (в старых системах разница была постоянной)
        differences = [observed_isns[i + 1] - observed_isns[i] for i in range(len(observed_isns)-1)]
        avg_increment = sum(differences) // len(differences) if differences else 64000
        predicted_isn = observed_isns[-1] + avg_increment
        
        print(f"Предсказанный следующий ISN: {predicted_isn} (средний инкремент: {avg_increment})")
        
        # Фаза 2: DoS на доверенный сервер
        print("\n[Фаза 3] DoS-атака на доверенный сервер (SYN flood):")
        print("→ Сервер перегружен и не может отправлять RST-пакеты")
        trusted.connection_state = "OVERWHELMED"  # Симуляция DoS
        
        # Фаза 3: Поддельный SYN от имени сервера
        print("\n[Фаза 4] Отправка поддельного SYN (spoofed packet):")
        print(f"→ Attacker отправляет X-терминалу SYN с IP-адресом сервера")
        
        # X-терминал думает, что это настоящий сервер
        print(f"\n[Фаза 5] X-терминал отвечает SYN/ACK на настоящий сервер:")
        # Симуляция того, что злоумышленник НЕ видит этот пакет
        syn_ack = target.send_syn_ack(remote_seq = 1000)  # SEQ от attacker подставлен
        print(f"→ Злоумышленник НЕ видит этот пакет (SEQ={syn_ack.seq}, ACK={syn_ack.ack})")
        
        # Фаза 4: Предсказание ISN и завершение рукопожатия
        print(f"\n[Фаза 6] Злоумышленник ПРЕДСКАЗЫВАЕТ ISN цели: {predicted_isn}")
        print(f"→ Отправка ACK с предсказанным номером:")
        
        # Симуляция того, что злоумышленник отправляет ACK с предсказанным SEQ+1
        attacker_ack_seq = predicted_isn
        attacker_ack_ack = 1001  # ожидаемый ACK от цели
        
        print(f"→ Attacker отправляет ACK (SEQ={attacker_ack_seq}, ACK={attacker_ack_ack})")
        print(f"→ Трёхстороннее рукопожатие завершено успешно!")
        
        # Фаза 5: Внедрение команды
        print("\n[Фаза 7] Внедрение вредоносной команды:")
        malicious_command = 'echo "+ +" >> .rhosts'
        print(f"→ Отправка данных: '{malicious_command}'")
        
        # Эмуляция успешного внедрения
        print(f"\n[РЕЗУЛЬТАТ] X-терминал принял команду!")
        print("→ Файл .rhosts изменён, теперь вход без пароля возможен с любого хоста.")
        
        # Фаза 6: После атаки
        print("\n[Фаза 8] Злоумышленник подключается по rsh без пароля:")
        print("→ Доступ к X-терминалу получен.")
        
        return True


class ModernAttackDefense:
    """Демонстрация почему современные системы защищены"""
    
    @staticmethod
    def demonstrate():
        print("\n" + "=" * 70)
        print("ПОЧЕМУ СОВРЕМЕННЫЕ СИСТЕМЫ ЗАЩИЩЕНЫ ОТ ТАКОЙ АТАКИ")
        print("=" * 70)
        
        # Современный генератор
        modern_gen = ModernSecureISNGenerator()
        
        print("\nСовременный TCP-стек (RFC 6528):")
        observed = []
        for i in range(5):
            isn = modern_gen.get_next_isn()
            observed.append(isn)
            print(f"  ISN {i + 1}: {isn}")
        
        print("\nРазницы между ISN:")
        for i in range(len(observed)-1):
            diff = observed[i + 1] - observed[i]
            print(f"  {observed[i + 1]} - {observed[i]} = {diff} (непредсказуемо)")
        
        print("\n→ Невозможно предсказать следующий ISN!")
        print("→ Атака Митника в современных сетях невозможна.")
        
        print("\nДополнительные защиты современного TCP:")
        print("• Случайные ISN (RFC 6528)")
        print("• TCP-AO (Authentication Option)")
        print("• SACK и ECN с проверкой целостности")
        print("• Защита от внеполосных атак (challenge ACK)")


def interactive_demo():
    """Интерактивная демонстрация для обучения"""
    print("\n" + "=" * 70)
    print("ИНТЕРАКТИВНАЯ ДЕМОНСТРАЦИЯ: ПОЧЕМУ TCP SPOOFING СЛОЖЕН")
    print("=" * 70)
    
    print("""
    Ключевые сложности подмены TCP (из вашего текста):
    
    1. Нужно подобрать не только порт, но и порядковый номер (32 бита)
    2. Злоумышленник не видит SYN/ACK от жертвы
    3. Доверенный хост отправляет RST, если получит неожиданный SYN/ACK
    4. ISN должны быть предсказуемыми (в старых системах)
    
    Атака Митника решила эти проблемы:
    - Предварительное наблюдение ISN для выявления закономерности
    - DoS на доверенный сервер (чтобы он не мог отправить RST)
    - Предсказание ISN и завершение рукопожатия
    """)
    
    run_sim = input("\nЗапустить симуляцию атаки? (y/n): ").lower()
    if run_sim == 'y':
        simulator = MitnickAttackSimulator()
        simulator.simulate_attack()
        ModernAttackDefense.demonstrate()
    
    print("\n" + "=" * 70)
    print("ВАЖНО: Эта программа — исключительно учебная симуляция.")
    print("Реальная реализация требует raw sockets и незаконна без разрешения.")
    print("=" * 70)


if __name__ == "__main__":
    interactive_demo()