import re
from collections import Counter

class MonoalphabeticCipher:
    """Моноалфавитный подстановочный шифр"""
    
    def __init__(self, key=None):
        """
        key: строка из 26 уникальных заглавных букв, задающая отображение a->key[0], b->key[1], ..., z->key[25]
        Если key не задан, создаётся случайный ключ.
        """
        import random
        self.alphabet = 'abcdefghijklmnopqrstuvwxyz'
        if key is None:
            key_list = list('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
            random.shuffle(key_list)
            key = ''.join(key_list)
        else:
            # Проверка ключа
            key = key.upper()
            assert len(key) == 26, "Ключ должен содержать 26 букв"
            assert set(key) == set('ABCDEFGHIJKLMNOPQRSTUVWXYZ'), "Ключ должен содержать все буквы A-Z"
        self.key = key
        # Отображение для шифрования (строчная буква -> заглавная)
        self.encrypt_map = {self.alphabet[i]: self.key[i] for i in range(26)}
        # Отображение для расшифровки (заглавная -> строчная)
        self.decrypt_map = {self.key[i]: self.alphabet[i] for i in range(26)}
    
    def encrypt(self, plaintext):
        """Шифрование: открытый текст (строчные буквы) -> зашифрованный текст (заглавные)"""
        result = []
        for ch in plaintext.lower():
            if ch in self.encrypt_map:
                result.append(self.encrypt_map[ch])
            else:
                result.append(ch)  # не буквы оставляем как есть
        return ''.join(result)
    
    def decrypt(self, ciphertext):
        """Расшифрование: зашифрованный текст (заглавные) -> открытый текст (строчные)"""
        result = []
        for ch in ciphertext:
            if ch in self.decrypt_map:
                result.append(self.decrypt_map[ch])
            else:
                result.append(ch)
        return ''.join(result)


class CipherCracker:
    """Криптоанализ моноалфавитного шифра с использованием частот и угадывания слов"""
    
    # Частоты букв в английском языке (убывающий порядок)
    ENGLISH_FREQ = 'etaoinshrdlcumwfgypbvkjxqz'
    
    # Частотность биграмм (самые частые)
    COMMON_BIGRAMS = ['th', 'he', 'in', 'er', 'an', 're', 'nd', 'at', 'on', 'nt']
    
    # Частотность триграмм
    COMMON_TRIGRAMS = ['the', 'and', 'ing', 'ion', 'tio', 'for', 'nde', 'has', 'nce', 'edt']
    
    def __init__(self, ciphertext):
        """
        ciphertext: зашифрованный текст (заглавные буквы, можно с пробелами и знаками)
        """
        # Извлекаем только буквы для анализа
        self.raw_ciphertext = ciphertext
        self.letters_only = re.sub(r'[^A-Z]', '', ciphertext.upper())
        self.freq = Counter(self.letters_only)
        
        # Текущее предполагаемое отображение (заглавная -> строчная)
        # Изначально неизвестно, заполняем None
        self.mapping = {ch: None for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'}
        # Обратное отображение (строчная -> заглавная) для удобства
        self.reverse_mapping = {ch: None for ch in 'abcdefghijklmnopqrstuvwxyz'}
    
    def get_sorted_by_freq(self):
        """Возвращает символы шифротекста, отсортированные по убыванию частоты"""
        return [item[0] for item in self.freq.most_common()]
    
    def apply_frequency_guess(self):
        """
        Шаг 1: сопоставляем самые частые символы шифротекста с самыми частыми буквами английского языка
        (e, t, a, o, ...)
        """
        cipher_sorted = self.get_sorted_by_freq()
        for i, cipher_char in enumerate(cipher_sorted):
            if i < len(self.ENGLISH_FREQ):
                guessed_plain = self.ENGLISH_FREQ[i]
                # Если это место ещё не занято
                if self.reverse_mapping[guessed_plain] is None:
                    self.set_mapping(cipher_char, guessed_plain)
        print("После частотного анализа:")
        self.print_mapping()
    
    def set_mapping(self, cipher_char, plain_char):
        """Устанавливает отображение cipher_char (заглавная) -> plain_char (строчная)"""
        if self.mapping[cipher_char] is not None:
            # Если уже было что-то другое, предупредим
            old = self.mapping[cipher_char]
            if old != plain_char:
                print(f"  Переопределяем {cipher_char}: {old} -> {plain_char}")
        self.mapping[cipher_char] = plain_char
        self.reverse_mapping[plain_char] = cipher_char
    
    def print_mapping(self):
        """Выводит текущее отображение в виде таблицы"""
        print("Текущее отображение (заглавная шифротекста -> строчная открытого текста):")
        for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
            p = self.mapping[c]
            if p is None:
                print(f"  {c} -> ?")
            else:
                print(f"  {c} -> {p}")
    
    def decrypt_with_current_mapping(self):
        """Расшифровывает текст с текущим отображением (неизвестные буквы заменяет на '_')"""
        result = []
        for ch in self.raw_ciphertext:
            if ch.isalpha() and ch.upper() in self.mapping:
                mapped = self.mapping[ch.upper()]
                if mapped is None:
                    result.append('_')
                else:
                    # Сохраняем регистр: если исходный был заглавным, отображаем строчную
                    result.append(mapped)
            else:
                result.append(ch)
        return ''.join(result)
    
    def find_word_pattern(self, word):
        """
        Возвращает паттерн слова: например, 'financial' -> 'abcdefghcib' (повторяющиеся буквы получают одинаковый индекс)
        """
        pattern = []
        seen = {}
        next_code = 0
        for ch in word.lower():
            if ch not in seen:
                seen[ch] = chr(ord('a') + next_code)
                next_code += 1
            pattern.append(seen[ch])
        return ''.join(pattern)
    
    def search_for_word(self, target_word):
        """
        Ищет в шифротексте позиции, где может находиться target_word,
        используя паттерн повторяющихся букв (как в примере с 'financial').
        Возвращает список позиций (индексов начала слова в letters_only).
        """
        pattern = self.find_word_pattern(target_word)
        word_len = len(target_word)
        positions = []
        
        # Перебираем все возможные стартовые позиции
        for i in range(len(self.letters_only) - word_len + 1):
            substring = self.letters_only[i:i + word_len]
            # Проверяем, совпадает ли паттерн повторений
            match = True
            for j1 in range(word_len):
                for j2 in range(j1 + 1, word_len):
                    if target_word[j1] == target_word[j2]:
                        if substring[j1] != substring[j2]:
                            match = False
                            break
                    else:
                        if substring[j1] == substring[j2]:
                            match = False
                            break
                if not match:
                    break
            if match:
                positions.append(i)
        return positions
    
    def apply_known_word(self, word, position):
        """
        Устанавливает отображения, исходя из предположения, что в позиции position
        в шифротексте (в letters_only) находится слово word.
        """
        print(f"\nПредполагаем, что слово '{word}' находится на позиции {position}")
        for i, plain_char in enumerate(word.lower()):
            cipher_char = self.letters_only[position + i]
            if self.mapping[cipher_char] is None:
                self.set_mapping(cipher_char, plain_char)
                print(f"  Установлено: {cipher_char} -> {plain_char}")
            elif self.mapping[cipher_char] != plain_char:
                print(f"  Конфликт: {cipher_char} уже отображается в {self.mapping[cipher_char]}, не в {plain_char}")
        self.print_mapping()
    
    def interactive_improve(self):
        """
        Интерактивный режим: пользователь может вводить догадки о словах и их позициях
        для улучшения расшифровки.
        """
        while True:
            print("\n" + "=" * 60)
            print("Текущая расшифровка:")
            print(self.decrypt_with_current_mapping())
            print("\nКоманды:")
            print("  word <слово> <позиция> - предположить слово на позиции (в letters_only)")
            print("  map <X> <a>            - вручную задать отображение X -> a")
            print("  freq                    - применить частотный анализ (повторно)")
            print("  quit                    - выход")
            cmd = input("> ").strip().lower()
            if cmd == 'quit':
                break
            elif cmd.startswith('word '):
                parts = cmd.split()
                if len(parts) == 3:
                    word = parts[1]
                    pos = int(parts[2])
                    self.apply_known_word(word, pos)
                else:
                    print("Формат: word <слово> <позиция>")
            elif cmd.startswith('map '):
                parts = cmd.split()
                if len(parts) == 3:
                    cipher_char = parts[1].upper()
                    plain_char = parts[2].lower()
                    if cipher_char in self.mapping and plain_char in 'abcdefghijklmnopqrstuvwxyz':
                        self.set_mapping(cipher_char, plain_char)
                    else:
                        print("Неверные символы")
                else:
                    print("Формат: map <X> <a>")
            elif cmd == 'freq':
                self.apply_frequency_guess()
            else:
                print("Неизвестная команда")


def demonstrate_example():
    """Демонстрация на примере из текста с бухгалтерской фирмой"""
    ciphertext_example = """
    CTBMN ВУСТС BTJDS QXBNS GSTJC BTSWX CTQTZ CQVUJ
    QJSGS TJQZZ MNQJS VLNSX VSZJU JDSTS JQUUS JUBXJ
    DSKSU JSNTK BGAQJ ZBGYQ TLCTZ BNYBN QJSW
    """
    # Очистим от лишних пробелов и приведём к заглавным
    clean_text = re.sub(r'[^A-Z]', '', ciphertext_example.upper())
    # Для наглядности разобьём на блоки по 5 (как в исходнике)
    print("Исходный шифротекст (буквы только):")
    print(clean_text)
    print("\n" + "=" * 60)
    
    cracker = CipherCracker(clean_text)
    
    # Шаг 1: частотный анализ
    print("\n--- Частотный анализ ---")
    cracker.apply_frequency_guess()
    
    # Шаг 2: поиск слова 'financial' (как в тексте)
    print("\n--- Поиск слова 'financial' ---")
    positions = cracker.search_for_word('financial')
    print(f"Найдены возможные позиции: {positions}")
    
    # В оригинальном примере авторы нашли позицию 31 (индексация с 0 или 1?)
    # Уточним: в тексте говорится "начинается в позиции 30" (если считать с 1)
    # При индексации с 0 это позиция 29. Покажем оба варианта.
    if positions:
        # Выберем первую подходящую позицию
        pos = positions[0]
        print(f"\nИспользуем позицию {pos} (индексация с 0)")
        cracker.apply_known_word('financial', pos)
    
    # Интерактивный режим для дальнейшего уточнения
    print("\n--- Интерактивный режим ---")
    cracker.interactive_improve()


def simple_test():
    """Простой тест: шифрование и расшифровка с известным ключом"""
    key = "QWERTYUIOPASDFGHJKLZXCVBNM"  # пример ключа
    cipher = MonoalphabeticCipher(key)
    plain = "attack at dawn"
    encrypted = cipher.encrypt(plain)
    decrypted = cipher.decrypt(encrypted)
    
    print("=== Простой тест ===")
    print(f"Ключ: {key}")
    print(f"Открытый текст: {plain}")
    print(f"Зашифрованный: {encrypted}")
    print(f"Расшифрованный: {decrypted}")
    print()


if __name__ == "__main__":
    simple_test()
    print("\n" + "=" * 60)
    print("=== Демонстрация криптоанализа ===")
    demonstrate_example()