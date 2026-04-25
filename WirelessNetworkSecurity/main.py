#!/usr/bin/env python3
"""
Безопасность беспроводных сетей: демонстрация уязвимостей (образовательная цель)
На основе текста о WEP, WPA2, WPA3 и атаках типа KRACK/DragonBlood

ВНИМАНИЕ: Это ТОЛЬКО для изучения принципов. Не используйте для реального взлома!
"""

import hashlib
import os
import zlib  # для crc32
from dataclasses import dataclass
from typing import Tuple, Optional

# Проверка наличия Crypto (pycryptodome)
try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("⚠️ Для работы AES требуется установка: pip install pycryptodome")
    print("   Без AES будет работать демонстрация WEP и рукопожатия WPA2\n")

# ========== 1. СИМУЛЯЦИЯ СЛАБОГО ШИФРОВАНИЯ WEP ==========
class WEP_Emulator:
    """Демонстрация слабости WEP: повторное использование ключей и уязвимость CRC"""
    
    @staticmethod
    def weak_rc4_prga(key: bytes, data: bytes) -> bytes:
        """Упрощённая имитация RC4 (реальный RC4 взломан через слабые IV)"""
        fake_stream = hashlib.md5(key + b"weak_salt").digest()
        # Повторяем поток, чтобы соответствовать длине данных
        result = bytearray()
        for i in range(len(data)):
            result.append(data[i] ^ fake_stream[i % len(fake_stream)])
        return bytes(result)
    
    @staticmethod
    def crc32_checksum(data: bytes) -> bytes:
        """CRC32 - годится для ошибок, но НЕ для криптозащиты (как в тексте)"""
        return zlib.crc32(data).to_bytes(4, 'little')
    
    @staticmethod
    def encrypt_wep(data: bytes, key: bytes) -> bytes:
        """WEP шифрование: данные + CRC32, затем XOR с RC4"""
        checksum = WEP_Emulator.crc32_checksum(data)
        plaintext = data + checksum
        iv = os.urandom(3)  # 24-битный IV - слишком короткий
        ciphertext = WEP_Emulator.weak_rc4_prga(key + iv, plaintext)
        return iv + ciphertext
    
    @staticmethod
    def demonstrate_weakness():
        """Показывает, почему WEP ломается за минуту"""
        print("\n" + "=" * 60)
        print("ДЕМОНСТРАЦИЯ УЯЗВИМОСТИ WEP (как в тексте: Стабблфилд, 2002)")
        print("=" * 60)
        
        key = b"secretkey123"
        
        packet1 = WEP_Emulator.encrypt_wep(b"Top secret: password = admin123", key)
        packet2 = WEP_Emulator.encrypt_wep(b"Top secret: password = admin123", key)
        
        iv1, iv2 = packet1[:3], packet2[:3]
        print(f"IV1: {iv1.hex()}  IV2: {iv2.hex()}")
        
        if iv1 == iv2:
            print("⚠️ СОВПАДЕНИЕ IV! Злоумышленник может восстановить ключ.")
            print("   (В реальности: aircrack-ng взламывает WEP < 1 минуты)")
        else:
            print("Даже разные IV не спасают — статистический анализ взламывает ключ.")
        
        test_data = b"Important secret data"
        crc1 = WEP_Emulator.crc32_checksum(test_data)
        crc2 = WEP_Emulator.crc32_checksum(b"Different data")
        print(f"\nCRC32 первого сообщения: {crc1.hex()}")
        print(f"CRC32 второго сообщения: {crc2.hex()}")
        print("⚠️ CRC32 можно подделать — он не защищает от намеренных изменений!")
        
        print("\n📌 Как сказано в тексте: WEP 'запрещает открытый доступ, но не обеспечивает никакой реальной защиты'")

# ========== 2. СИМУЛЯЦИЯ 4-СТОРОННЕГО РУКОПОЖАТИЯ WPA2 ==========
@dataclass
class AccessPoint:
    """Точка доступа (AP)"""
    ssid: str
    mac: bytes
    pmk: bytes  # Pairwise Master Key

class WPA2_Handshake:
    """Демонстрация 4-стороннего рукопожатия (илл. 8.44 из текста)"""
    
    def __init__(self, ap: AccessPoint, client_mac: bytes):
        self.ap = ap
        self.client_mac = client_mac
        
    @staticmethod
    def pbkdf2_sha1(password: str, ssid: str, iterations: int = 4096) -> bytes:
        """PMK = PBKDF2(пароль, SSID)"""
        return hashlib.pbkdf2_hmac('sha1', password.encode(), ssid.encode(), iterations, 32)
    
    @staticmethod
    def derive_session_key(pmk: bytes, ap_nonce: bytes, client_nonce: bytes, ap_mac: bytes, client_mac: bytes) -> bytes:
        """PTK = PRF(PMK + ANonce + SNonce + AP_MAC + Client_MAC)"""
        data = ap_nonce + client_nonce + ap_mac + client_mac
        return hashlib.pbkdf2_hmac('sha256', pmk, data, 1, 64)
    
    def perform_handshake(self) -> Tuple[bool, Optional[bytes]]:
        """Симуляция 4-стороннего рукопожатия"""
        print("\n" + "=" * 60)
        print("СИМУЛЯЦИЯ 4-СТОРОННЕГО РУКОПОЖАТИЯ WPA2 (как на илл. 8.44)")
        print("=" * 60)
        
        ap_nonce = os.urandom(32)
        print(f"[AP] -> Client: ANonce = {ap_nonce[:8].hex()}... (открыто)")
        
        client_nonce = os.urandom(32)
        ptk = self.derive_session_key(self.ap.pmk, ap_nonce, client_nonce, self.ap.mac, self.client_mac)
        print(f"[Client] -> AP: SNonce = {client_nonce[:8].hex()}..., PTK = {ptk[:16].hex()}...")
        
        mic_data = ap_nonce + client_nonce + self.ap.mac + self.client_mac
        mic = hashlib.sha256(ptk + mic_data).digest()[:16]
        print(f"         MIC = {mic.hex()}")
        
        ap_ptk = self.derive_session_key(self.ap.pmk, ap_nonce, client_nonce, self.ap.mac, self.client_mac)
        ap_mic = hashlib.sha256(ap_ptk + mic_data).digest()[:16]
        
        if ap_mic == mic:
            print("[AP] MIC проверен ✅ — клиент аутентифицирован")
            gtk = os.urandom(32)
            print(f"[AP] -> Client: GTK = {gtk[:8].hex()}... + MIC")
            
            confirm = hashlib.sha256(ptk + b"confirm").digest()[:16]
            print(f"[Client] -> AP: Подтверждение = {confirm.hex()}")
            return True, ptk
        else:
            print("[AP] MIC не совпал ❌")
            return False, None

    @staticmethod
    def demonstrate_krack_attack():
        """Объяснение атаки KRACK"""
        print("\n" + "=" * 60)
        print("АТАКА KRACK (переустановка ключа) — уязвимость WPA2")
        print("=" * 60)
        print("💀 Механизм: злоумышленник заставляет клиента переустановить")
        print("   уже использованный ключ, обнуляя счётчик пакетов (nonce).")
        print("\n📌 Из текста: 'главным улучшением WPA3 является переработанный")
        print("   механизм рукопожатия Dragonfly'")

# ========== 3. БЕЗОПАСНЫЙ РЕЖИМ: CCMP (WPA2/WPA3) ==========
class CCMP_Protocol:
    """CCMP = AES в режиме счетчика + CBC-MAC"""
    
    @staticmethod
    def encrypt_ccmp(plaintext: bytes, key: bytes, packet_number: int) -> bytes:
        """Шифрование через AES-CTR + MIC"""
        if not CRYPTO_AVAILABLE:
            # Эмуляция без реального AES
            fake_enc = hashlib.sha256(key + packet_number.to_bytes(8, 'little') + plaintext).digest()[:len(plaintext)]
            mic = hashlib.sha256(key + plaintext).digest()[:16]
            return fake_enc + mic
        
        # Правильный способ: создаём счётчик
        # Используем 8-байтовый счётчик (nonce) + 8 байтов для счётчика пакетов
        ctr = Counter.new(128, initial_value=packet_number, little_endian=True)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        ciphertext = cipher.encrypt(plaintext)
        
        # CBC-MAC для MIC (128 бит)
        mic_key = hashlib.sha256(key + b"mic").digest()[:16]
        mic = hashlib.sha256(mic_key + plaintext).digest()[:16]
        
        return ciphertext + mic
    
    @staticmethod
    def decrypt_ccmp(encrypted: bytes, key: bytes, packet_number: int) -> Optional[bytes]:
        """Расшифровка и проверка MIC"""
        if not CRYPTO_AVAILABLE:
            print("   (Эмуляция: без pycryptodome)")
            return b"Decrypted (emulated)"
        
        if len(encrypted) < 16:
            return None
            
        ciphertext = encrypted[:-16]
        received_mic = encrypted[-16:]
        
        ctr = Counter.new(128, initial_value = packet_number, little_endian = True)
        cipher = AES.new(key, AES.MODE_CTR, counter = ctr)
        plaintext = cipher.decrypt(ciphertext)
        
        mic_key = hashlib.sha256(key + b"mic").digest()[:16]
        calculated_mic = hashlib.sha256(mic_key + plaintext).digest()[:16]
        
        if calculated_mic == received_mic:
            return plaintext
        else:
            print("❌ Целостность нарушена!")
            return None
    
    @staticmethod
    def demonstrate():
        print("\n" + "=" * 60)
        print("БЕЗОПАСНЫЙ ПРОТОКОЛ: CCMP (WPA2/WPA3) — AES-128/256")
        print("=" * 60)
        
        key = hashlib.sha256(b"session_key_from_handshake").digest()
        message = b"Secret data: credit card 4111-1111-1111-1111"
        
        print(f"Original message: {message}")
        
        try:
            encrypted = CCMP_Protocol.encrypt_ccmp(message, key, packet_number = 1)
            print(f"Encrypted + MIC: {encrypted[:32].hex()}...")
            
            decrypted = CCMP_Protocol.decrypt_ccmp(encrypted, key, packet_number = 1)
            print(f"Decrypted: {decrypted}")
            
            # Проверка целостности
            if CRYPTO_AVAILABLE and decrypted == message:
                print("\n✅ CCMP успешно обеспечивает конфиденциальность и целостность!")
                
        except Exception as e:
            print(f"⚠️ Ошибка при работе AES: {e}")
            print("   (эмуляция работает корректно)")

# ========== 4. ДЕМОНСТРАЦИЯ УЯЗВИМОСТИ DRAGONBLOOD (WPA3) ==========
def dragonblood_demonstration():
    """Объяснение атаки DragonBlood на WPA3"""
    print("\n" + "=" * 60)
    print("АТАКА DRAGONBLOOD (WPA3) — 'сводит на нет преимущества WPA3'")
    print("=" * 60)
    print("""
    Mechanism of attack:
    1. WPA3 uses Dragonfly protocol (SAE handshake)
    2. Vulnerability in side-channel - password can be determined by response time
    3. Dictionary attack becomes possible again
    
    Quote from the text:
    'In April 2019, researchers identified an attack vector called
    DragonBlood, which negates many of WPA3's security advantages'
    """)
    
    common_passwords = ["password", "12345678", "qwerty", "admin", "wifi123"]
    target_pmk = hashlib.pbkdf2_hmac('sha256', b"wifi123", b"HomeWiFi", 4096, 32)
    
    print("Dictionary attack simulation:")
    for pwd in common_passwords:
        pmk = hashlib.pbkdf2_hmac('sha256', pwd.encode(), b"HomeWiFi", 4096, 32)
        if pmk == target_pmk:
            print(f"✅ PASSWORD FOUND: {pwd}")
            break
    else:
        print("❌ Password not found")

# ========== 5. РАДИОКАНАЛ ==========
def radio_channel_demonstration():
    """Как радиосигнал 'протекает' через брандмауэр"""
    print("\n" + "=" * 60)
    print("RADIO CHANNEL - SPY'S DREAM (quote from the text)")
    print("=" * 60)
    print("""
    802.11 range -> up to 100 meters
    Attacker on parking lot can intercept traffic
    Firewall and VPN DO NOT PROTECT against radio interception!
    
    Solutions from the text:
    - WPA2/WPA3 with CCMP (AES)
    - 802.1X + RADIUS for enterprise use
    - Avoid WEP and TKIP
    - Regularly update access point firmware
    """)

# ========== ИНФОРМАЦИЯ ==========
def show_install_info():
    if not CRYPTO_AVAILABLE:
        print("\n" + "=" * 60)
        print("📦 РЕКОМЕНДАЦИЯ ПО УСТАНОВКЕ")
        print("=" * 60)
        print("Для полноценной работы AES шифрования выполните:")
        print("  pip install pycryptodome")

# ========== ГЛАВНАЯ ФУНКЦИЯ ==========
def main():
    print("🔐 WIRELESS NETWORK SECURITY DEMONSTRATION")
    print("Based on text about WEP, WPA2, WPA3 and attacks")
    print("⚠️  FOR EDUCATIONAL PURPOSES ONLY")
    
    # 1. WEP
    WEP_Emulator.demonstrate_weakness()
    
    # 2. WPA2 handshake
    ap = AccessPoint(
        ssid = "HomeWiFi",
        mac = b"\x00\x11\x22\x33\x44\x55",
        pmk = WPA2_Handshake.pbkdf2_sha1("my_secret_password", "HomeWiFi")
    )
    handshake = WPA2_Handshake(ap, client_mac = b"\xAA\xBB\xCC\xDD\xEE\xFF")
    success, ptk = handshake.perform_handshake()
    
    # 3. KRACK
    WPA2_Handshake.demonstrate_krack_attack()
    
    # 4. CCMP
    CCMP_Protocol.demonstrate()
    
    # 5. DragonBlood
    dragonblood_demonstration()
    
    # 6. Radio channel
    radio_channel_demonstration()
    
    # 7. Info
    show_install_info()
    
    print("\n" + "=" * 60)
    print("CONCLUSION (as in the text):")
    print("""
    ✅ WEP - completely compromised (do not use)
    ⚠️ WPA2 - secure if configured properly, but vulnerable to KRACK
    🔄 WPA3 - improved, but attacks found (DragonBlood)
    🛡️ Always use CCMP (AES), avoid TKIP
    📡 For enterprise use - 802.1X with authentication server
    """)

if __name__ == "__main__":
    main()