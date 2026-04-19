import random

# ------------------------------------------------------------
# 1. Текст -> битовая строка (7-битный ASCII)
# ------------------------------------------------------------
def text_to_bits(text: str) -> str:
    bits = ''
    for ch in text:
        # Берем только младшие 7 бит (0-127)
        code = ord(ch) & 0x7F
        bits += format(code, '07b')
    return bits

def bits_to_text(bits: str) -> str:
    chars = []
    for i in range(0, len(bits), 7):
        byte = bits[i:i+7]
        if len(byte) == 7:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

# ------------------------------------------------------------
# 2. Выравнивание сообщений до одинаковой длины
# ------------------------------------------------------------
def align_lengths(msg1: str, msg2: str):
    """Дополняет пробелами более короткое сообщение"""
    max_len = max(len(msg1), len(msg2))
    return msg1.ljust(max_len), msg2.ljust(max_len)

# ------------------------------------------------------------
# 3. Генерация случайного ключа
# ------------------------------------------------------------
def generate_random_key(length_bits: int) -> str:
    return ''.join(str(random.getrandbits(1)) for _ in range(length_bits))

# ------------------------------------------------------------
# 4. XOR двух битовых строк
# ------------------------------------------------------------
def xor_bits(bits1: str, bits2: str) -> str:
    if len(bits1) != len(bits2):
        raise ValueError(f"Длины не совпадают: {len(bits1)} vs {len(bits2)}")
    return ''.join(str(int(b1) ^ int(b2)) for b1, b2 in zip(bits1, bits2))

# ------------------------------------------------------------
# 5. Шифрование/дешифрование
# ------------------------------------------------------------
def encrypt(plaintext: str, key_bits: str) -> str:
    plain_bits = text_to_bits(plaintext)
    if len(plain_bits) != len(key_bits):
        raise ValueError(f"Длина ключа ({len(key_bits)} бит) != длине сообщения ({len(plain_bits)} бит)")
    return xor_bits(plain_bits, key_bits)

def decrypt(cipher_bits: str, key_bits: str) -> str:
    plain_bits = xor_bits(cipher_bits, key_bits)
    return bits_to_text(plain_bits)

# ------------------------------------------------------------
# ГЛАВНАЯ ДЕМОНСТРАЦИЯ
# ------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 70)
    print("ОДНОРАЗОВЫЙ БЛОКНОТ (OTP) — абсолютно стойкое шифрование")
    print("=" * 70)
    
    # Исходные сообщения (могут быть разной длины - программа выровняет)
    message1 = "I love you"
    message2 = "Elvis lives"
    
    print(f"\nИсходные сообщения:")
    print(f"  A: '{message1}' (длина: {len(message1)} символов)")
    print(f"  B: '{message2}' (длина: {len(message2)} символов)")
    
    # Выравниваем длины (как в реальном OTP — сообщения фиксированной длины)
    msg1_aligned, msg2_aligned = align_lengths(message1, message2)
    
    if len(message1) != len(message2):
        print(f"\n⚠️  Длины разные! Выравниваем пробелами:")
        print(f"  A: '{msg1_aligned}' ({len(msg1_aligned)} символов)")
        print(f"  B: '{msg2_aligned}' ({len(msg2_aligned)} символов)")
    
    # Переводим в биты
    bits1 = text_to_bits(msg1_aligned)
    bits2 = text_to_bits(msg2_aligned)
    
    print(f"\nБитовая длина: {len(bits1)} бит ({len(bits1) // 7} символов)")
    
    # Генерируем случайный ключ для сообщения A
    key1 = generate_random_key(len(bits1))
    print(f"\nКЛЮЧ 1 (случайный): {key1[:50]}... (первые 50 бит)")
    
    # Шифруем сообщение A
    cipher = encrypt(msg1_aligned, key1)
    print(f"\nЗашифрованный текст (биты): {cipher[:50]}... (первые 50 бит)")
    
    # Расшифровка правильным ключом
    decrypted1 = decrypt(cipher, key1)
    print(f"\nРасшифровка ключом 1: '{decrypted1.rstrip()}' ✓")
    
    # ----------------------------------------------------
    # КЛЮЧЕВАЯ ДЕМОНСТРАЦИЯ
    # ----------------------------------------------------
    print("\n" + "=" * 70)
    print("ГЛАВНОЕ СВОЙСТВО OTP (из вашего текста):")
    print("Из одного шифротекста можно получить ЛЮБОЕ сообщение")
    print("=" * 70)
    
    # Вычисляем ключ 2 для получения сообщения B из ТОГО ЖЕ шифротекста
    # cipher = bits1 XOR key1
    # хотим: cipher XOR key2 = bits2
    # значит: key2 = cipher XOR bits2
    key2 = xor_bits(cipher, bits2)
    print(f"\nКЛЮЧ 2 (подобранный для '{msg2_aligned.strip()}'):")
    print(f"  {key2[:50]}... (первые 50 бит)")
    
    # Расшифровываем ТОТ ЖЕ шифротекст ключом 2
    decrypted2 = decrypt(cipher, key2)
    print(f"\nРасшифровка ТОГО ЖЕ шифротекста ключом 2:")
    print(f"  '{decrypted2.rstrip()}'")
    
    # Проверяем, что получили именно message2
    if decrypted2.rstrip() == message2:
        print(f"  ✓ Совпадает с '{message2}'")
    
    print("\n" + "=" * 70)
    print("ВЫВОД (цитата из вашего текста):")
    print('"В зашифрованном сообщении не содержится никаких сведений')
    print('для взломщика, поскольку любой открытый текст нужной длины')
    print('является равновероятным кандидатом."')
    print("=" * 70)
    
    # Дополнительно: показываем, что оба сообщения возможны
    print("\nСтатистическая проверка:")
    print(f"  Сообщение A существует с ключом 1: '{message1}'")
    print(f"  Сообщение B существует с ключом 2: '{message2}'")
    print(f"  Без ключа невозможно определить, какое из них истинное!")
    
    # ----------------------------------------------------
    # ПРЕДУПРЕЖДЕНИЕ
    # ----------------------------------------------------
    print("\n" + "⚠️ " * 25)
    print("ВАЖНОЕ ПРАВИЛО ОДНОРАЗОВОГО БЛОКНОТА:")
    print("1. Ключ должен быть истинно случайным")
    print("2. Ключ должен быть длиной не меньше сообщения")
    print("3. Ключ используется ТОЛЬКО ОДИН РАЗ")
    print("4. Ключ должен храниться в секрете")
    print("⚠️ " * 25)
    
    # Демонстрация нарушения правила №3
    print("\n[ДЕМОНСТРАЦИЯ ОШИБКИ] Повторное использование ключа:")
    message3 = "Secret!!"
    print(f"  Третье сообщение: '{message3}'")
    
    # ОШИБКА: используем тот же key1 снова
    try:
        cipher3 = encrypt(message3.ljust(len(msg1_aligned)), key1)
        xor_ciphers = xor_bits(cipher, cipher3)
        print(f"  XOR двух шифротекстов = {xor_ciphers[:40]}...")
        print("  → Это даёт информацию взломщику! НИКОГДА так не делайте.")
    except Exception as e:
        print(f"  Ошибка: {e}")