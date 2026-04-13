#!/usr/bin/env python3
"""
ТРАНСПОРТНАЯ АДРЕСАЦИЯ: TSAP, NSAP И МЕХАНИЗМЫ ОБНАРУЖЕНИЯ
===========================================================

Полная реализация на основе текста из учебника по компьютерным сетям.
"""

import socket
import threading
import select
import time
import sys
from datetime import datetime

# ============================================================================
# КОНСТАНТЫ
# ============================================================================

LOCAL_NSAP = "127.0.0.1"

WELL_KNOWN_TSAP = {
    'echo': 7,
    'discard': 9,
    'daytime': 13,
    'mail': 25,
    'http': 80,
    'time': 37,
}

PORTMAPPER_TSAP = 111
DYNAMIC_TSAP_START = 49152
DYNAMIC_TSAP_END = 65535


# ============================================================================
# ЧАСТЬ 1: СОПОСТАВИТЕЛЬ ПОРТОВ (PORT MAPPER)
# ============================================================================

class PortMapper:
    def __init__(self):
        self.services = {}
        self.lock = threading.Lock()
        self.server_socket = None
        self.running = False
        
    def register(self, service_name, tsap_address):
        with self.lock:
            self.services[service_name] = tsap_address
            print(f"  [PortMapper] REGISTERED: '{service_name}' -> TSAP {tsap_address}")
            return True
            
    def unregister(self, service_name):
        with self.lock:
            if service_name in self.services:
                del self.services[service_name]
                print(f"  [PortMapper] UNREGISTERED: '{service_name}'")
                return True
            return False
            
    def lookup(self, service_name):
        with self.lock:
            tsap = self.services.get(service_name)
            if tsap:
                print(f"  [PortMapper] LOOKUP: '{service_name}' -> TSAP {tsap}")
            else:
                print(f"  [PortMapper] LOOKUP: '{service_name}' -> NOT FOUND")
            return tsap
            
    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((LOCAL_NSAP, PORTMAPPER_TSAP))
        self.server_socket.listen(5)
        self.running = True
        
        print(f"\n  [PortMapper] Server started on TSAP {PORTMAPPER_TSAP} (NSAP: {LOCAL_NSAP})")
        
        while self.running:
            try:
                client_socket, client_addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_addr)
                )
                client_thread.daemon = True
                client_thread.start()
            except:
                break
                
    def stop_server(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            
    def _handle_client(self, client_socket, client_addr):
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if not data:
                return
                
            parts = data.strip().split()
            if not parts:
                return
                
            command = parts[0].upper()
            
            if command == "LOOKUP" and len(parts) >= 2:
                service_name = parts[1]
                tsap = self.lookup(service_name)
                response = f"OK {tsap}" if tsap else "NOT_FOUND"
                
            elif command == "REGISTER" and len(parts) >= 3:
                service_name = parts[1]
                tsap = int(parts[2])
                self.register(service_name, tsap)
                response = "REGISTERED"
                
            elif command == "UNREGISTER" and len(parts) >= 2:
                service_name = parts[1]
                self.unregister(service_name)
                response = "UNREGISTERED"
                
            elif command == "LIST":
                services = self.list_services()
                response = "SERVICES " + " ".join(f"{k}:{v}" for k, v in services.items())
                
            else:
                response = "ERROR Unknown command"
                
            client_socket.send(response.encode('utf-8'))
            
        except Exception as e:
            print(f"  [PortMapper] Error: {e}")
        finally:
            client_socket.close()
    
    def list_services(self):
        with self.lock:
            return self.services.copy()
    
    @staticmethod
    def client_lookup(service_name, host=LOCAL_NSAP, port=PORTMAPPER_TSAP):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            sock.send(f"LOOKUP {service_name}".encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            sock.close()
            
            if response.startswith("OK"):
                return int(response.split()[1])
            return None
        except Exception as e:
            print(f"  [PortMapper Client] Error: {e}")
            return None


# ============================================================================
# ЧАСТЬ 2: INETD-ПОДОБНЫЙ СЕРВЕР
# ============================================================================

class InetdServer:
    def __init__(self):
        self.services = {}
        self.sockets = []
        self.running = False
        
    def register_service(self, tsap, service_name, handler=None):
        self.services[tsap] = {
            'name': service_name,
            'handler': handler
        }
        print(f"  [inetd] Registered '{service_name}' on TSAP {tsap}")
        
    def start(self):
        for tsap in self.services:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((LOCAL_NSAP, tsap))
                sock.listen(5)
                self.sockets.append((tsap, sock))
                print(f"  [inetd] Listening on TSAP {tsap} ({self.services[tsap]['name']})")
            except Exception as e:
                print(f"  [inetd] Error binding to TSAP {tsap}: {e}")
                
        self.running = True
        print(f"\n  [inetd] Server started, waiting for connections...")
        
        while self.running:
            readable = [sock for _, sock in self.sockets]
            try:
                ready, _, _ = select.select(readable, [], [], 1)
            except:
                break
                
            for tsap, sock in [(t, s) for t, s in self.sockets if s in ready]:
                try:
                    client_socket, client_addr = sock.accept()
                    print(f"  [inetd] Received connection on TSAP {tsap} from {client_addr}")
                    
                    handler_thread = threading.Thread(
                        target=self._handle_connection,
                        args=(tsap, client_socket, client_addr)
                    )
                    handler_thread.daemon = True
                    handler_thread.start()
                except Exception as e:
                    print(f"  [inetd] Accept error: {e}")
                    
    def stop(self):
        self.running = False
        for _, sock in self.sockets:
            sock.close()
            
    def _handle_connection(self, tsap, client_socket, client_addr):
        service = self.services.get(tsap)
        if not service:
            client_socket.close()
            return
            
        service_name = service['name']
        handler = service['handler']
        
        print(f"  [inetd] Launching service '{service_name}' on demand for {client_addr}")
        
        if handler:
            try:
                handler(client_socket, client_addr, service_name)
            except Exception as e:
                print(f"  [inetd] Error in handler {service_name}: {e}")
        else:
            self._default_handler(service_name, client_socket, client_addr)
            
        client_socket.close()
        
    def _default_handler(self, service_name, client_socket, client_addr):
        messages = {
            'echo': "Echo service ready. Send me something.\n",
            'daytime': f"Current time: {datetime.now().ctime()}\n",
            'discard': "Discard service active.\n",
            'mail': "220 Mail server ready (started via inetd)\n",
        }
        
        msg = messages.get(service_name, f"Service '{service_name}' started via inetd.\n")
        
        try:
            client_socket.send(msg.encode())
            
            if service_name == 'echo':
                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                    client_socket.send(data)
            elif service_name == 'mail':
                data = client_socket.recv(1024)
                if data:
                    print(f"  [inetd] Received mail: {data.decode()[:100]}...")
                    client_socket.send(b"250 Message will be delivered\n")
            else:
                client_socket.recv(1024)
                
        except Exception as e:
            print(f"  [inetd] Error in service {service_name}: {e}")


# ============================================================================
# ЧАСТЬ 3: ТРАНСПОРТНЫЙ КЛИЕНТ
# ============================================================================

class TransportClient:
    def __init__(self, remote_nsap=LOCAL_NSAP):
        self.remote_nsap = remote_nsap
        
    def connect_to_well_known(self, service_name):
        if service_name not in WELL_KNOWN_TSAP:
            print(f"  [Client] Error: service '{service_name}' not found in well-known TSAPs")
            return None
            
        tsap = WELL_KNOWN_TSAP[service_name]
        print(f"  [Client] Connecting to '{service_name}' on TSAP {tsap}")
        return self._connect(tsap)
        
    def connect_via_portmapper(self, service_name, portmapper_host=LOCAL_NSAP):
        print(f"  [Client] Querying TSAP for '{service_name}' via portmapper...")
        tsap = PortMapper.client_lookup(service_name, portmapper_host)
        
        if tsap is None:
            print(f"  [Client] Service '{service_name}' not found in portmapper registry")
            return None
            
        print(f"  [Client] Portmapper returned TSAP {tsap}, connecting...")
        return self._connect(tsap)
        
    def connect_direct(self, tsap):
        print(f"  [Client] Direct connection to TSAP {tsap}")
        return self._connect(tsap)
        
    def _connect(self, tsap):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.remote_nsap, tsap))
            print(f"  [Client] Transport connection ESTABLISHED: TSAP {tsap} on {self.remote_nsap}")
            return sock
        except Exception as e:
            print(f"  [Client] Connection error to TSAP {tsap}: {e}")
            return None
            
    def send(self, sock, message):
        if sock:
            sock.send(message.encode() if isinstance(message, str) else message)
            
    def receive(self, sock, max_bytes=4096):
        if sock:
            try:
                return sock.recv(max_bytes).decode()
            except:
                return ""
        return ""
        
    def close(self, sock):
        if sock:
            sock.close()
            print("  [Client] Transport connection CLOSED")


# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def run_mail_server_on_tsap(tsap=1522):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCAL_NSAP, tsap))
    server_socket.listen(5)
    
    print(f"\n  [MailServer] Mail server started on TSAP {tsap}")
    
    def handle_mail(client_socket, addr):
        client_socket.send(b"220 Mail server ready\n")
        data = client_socket.recv(1024)
        if data:
            print(f"  [MailServer] Received: {data.decode()[:80]}...")
            client_socket.send(b"250 Message will be delivered\n")
        client_socket.close()
    
    def run():
        while True:
            client, addr = server_socket.accept()
            threading.Thread(target=handle_mail, args=(client, addr), daemon=True).start()
    
    threading.Thread(target=run, daemon=True).start()
    return server_socket


def run_dynamic_service_on_tsap(tsap, service_name, response_message):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LOCAL_NSAP, tsap))
    server_socket.listen(5)
    
    print(f"\n  [DynamicService] Service '{service_name}' started on TSAP {tsap}")
    
    def run():
        while True:
            client, addr = server_socket.accept()
            try:
                client.send(response_message.encode())
            except:
                pass
            client.close()
    
    threading.Thread(target=run, daemon=True).start()
    return server_socket


# ============================================================================
# ДЕМОНСТРАЦИИ
# ============================================================================

def demo_1_well_known_tsap():
    print("\n" + "┌" + "─" * 58 + "┐")
    print("│ DEMO 1: WELL-KNOWN TSAP (like /etc/services)              │")
    print("└" + "─" * 58 + "┘")
    
    daytime_server = run_dynamic_service_on_tsap(13, "daytime", datetime.now().ctime())
    time.sleep(0.5)
    
    client = TransportClient()
    sock = client.connect_to_well_known('daytime')
    
    if sock:
        response = client.receive(sock)
        print(f"  [Client] Server response: {response.strip()}")
        client.close(sock)
    
    return True


def demo_2_portmapper():
    print("\n" + "┌" + "─" * 58 + "┐")
    print("│ DEMO 2: PORT MAPPER (Telephone directory service)         │")
    print("└" + "─" * 58 + "┘")
    
    portmapper = PortMapper()
    pm_thread = threading.Thread(target=portmapper.start_server, daemon=True)
    pm_thread.start()
    time.sleep(1)
    
    dynamic_tsap = 50000
    portmapper.register("calculator_service", dynamic_tsap)
    
    calc_server = run_dynamic_service_on_tsap(
        dynamic_tsap, 
        "calculator_service", 
        "Calculator service ready. 2 + 2 = 4\n"
    )
    
    time.sleep(0.5)
    
    client = TransportClient()
    sock = client.connect_via_portmapper("calculator_service")
    
    if sock:
        response = client.receive(sock)
        print(f"  [Client] Service response: {response.strip()}")
        client.close(sock)
    
    portmapper.unregister("calculator_service")
    portmapper.stop_server()
    
    return True


def demo_3_inetd():
    print("\n" + "┌" + "─" * 58 + "┐")
    print("│ DEMO 3: INITIAL CONNECTION PROTOCOL (inetd-like)           │")
    print("└" + "─" * 58 + "┘")
    
    inetd = InetdServer()
    inetd.register_service(7, "echo")
    inetd.register_service(13, "daytime")
    inetd.register_service(19, "discard")
    
    inetd_thread = threading.Thread(target=inetd.start, daemon=True)
    inetd_thread.start()
    time.sleep(1)
    
    client = TransportClient()
    
    print("\n  [Client] Connecting to echo service (TSAP 7)...")
    sock = client.connect_direct(7)
    if sock:
        client.send(sock, "Hello, inetd echo service!\n")
        response = client.receive(sock)
        print(f"  [Client] Echo response: {response.strip()}")
        client.close(sock)
    
    print("\n  [Client] Connecting to daytime service (TSAP 13)...")
    sock = client.connect_direct(13)
    if sock:
        response = client.receive(sock)
        print(f"  [Client] Time response: {response.strip()}")
        client.close(sock)
    
    inetd.stop()
    return True


def demo_4_full_scenario_from_text():
    print("\n" + "┌" + "─" * 58 + "┐")
    print("│ DEMO 4: FULL SCENARIO FROM TEXTBOOK (Mail server)          │")
    print("└" + "─" * 58 + "┘")
    
    MAIL_TSAP = 1522
    
    mail_server = run_mail_server_on_tsap(MAIL_TSAP)
    time.sleep(0.5)
    
    print(f"\n  Step 1: Mail server listening on TSAP {MAIL_TSAP}")
    print("  Step 2: Client process binds to local TSAP 1208")
    
    client = TransportClient()
    sock = client.connect_direct(MAIL_TSAP)
    
    if sock:
        welcome = client.receive(sock)
        print(f"  Steps 3-4: Server response: {welcome.strip()}")
        
        message = """HELO client.example.com
MAIL FROM: <user@host1>
RCPT TO: <recipient@host2>
DATA
From: user@host1
To: recipient@host2
Subject: Test message

Hello! This is a test email message.
.
QUIT
"""
        print(f"\n  Step 5: Client sending email message:")
        print(f"  ---\n{message}---")
        client.send(sock, message)
        
        response = client.receive(sock, 1024)
        print(f"\n  Step 6: Mail server responded: {response.strip()}")
        
        client.close(sock)
        print("  Step 7: Transport connection closed")
    
    print("\n  Note: Other servers on host 2 may be bound to their own TSAPs")
    
    return True


def demo_5_comparison():
    print("\n" + "┌" + "─" * 58 + "┐")
    print("│ DEMO 5: PORT MAPPER vs INETD COMPARISON                    │")
    print("└" + "─" * 58 + "┘")
    
    print("""
    +-------------------------------------------------------------------+
    |  PORT MAPPER                                                      |
    +-------------------------------------------------------------------+
    |  Analogy: Telephone directory service                             |
    |                                                                   |
    |  Process:                                                         |
    |  1. Service registers in portmapper (name -> TSAP)               |
    |  2. Client asks portmapper: "Where is service X?"                |
    |  3. Portmapper answers: "On TSAP Y"                              |
    |  4. Client connects directly to TSAP Y                           |
    |                                                                   |
    |  Features:                                                        |
    |  - Requires well-known portmapper TSAP (111)                     |
    |  - Services can use dynamic TSAPs                                |
    |  - Services run continuously                                     |
    +-------------------------------------------------------------------+
    
    +-------------------------------------------------------------------+
    |  INETD (Initial Connection Protocol)                             |
    +-------------------------------------------------------------------+
    |  Analogy: Dispatcher with on-demand wakeup                       |
    |                                                                   |
    |  Process:                                                         |
    |  1. inetd listens on multiple TSAPs                              |
    |  2. Server processes NOT initially running                       |
    |  3. On incoming connection, inetd STARTS the server              |
    |  4. Server handles request and exits                             |
    |                                                                   |
    |  Features:                                                        |
    |  - Saves resources (rare services not in memory)                 |
    |  - Uses well-known TSAPs                                         |
    |  - First request may be slower (startup time)                    |
    +-------------------------------------------------------------------+
    """)
    
    return True


# ============================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# ============================================================================

def main():
    print("""
+--------------------------------------------------------------------+
|                                                                    |
|     TRANSPORT ADDRESSING: TSAP, NSAP AND DISCOVERY MECHANISMS      |
|                                                                    |
|     TSAP - Transport Service Access Point (port)                   |
|     NSAP - Network Service Access Point (IP address)               |
|                                                                    |
|     Based on textbook chapter on computer networks                 |
|                                                                    |
+--------------------------------------------------------------------+
    """)
    
    print("\nSelect demonstration:")
    print("  1. Well-known TSAP (like /etc/services)")
    print("  2. Port Mapper (telephone directory service)")
    print("  3. Initial Connection Protocol (inetd-like)")
    print("  4. Full textbook scenario (mail server)")
    print("  5. Port Mapper vs inetd comparison")
    print("  6. ALL demonstrations (sequential)")
    print("  0. Exit")
    
    choice = input("\nYour choice (0-6): ").strip()
    
    if choice == "1":
        demo_1_well_known_tsap()
    elif choice == "2":
        demo_2_portmapper()
    elif choice == "3":
        demo_3_inetd()
    elif choice == "4":
        demo_4_full_scenario_from_text()
    elif choice == "5":
        demo_5_comparison()
    elif choice == "6":
        print("\n" + "=" * 60)
        print("RUNNING ALL DEMONSTRATIONS SEQUENTIALLY")
        print("=" * 60)
        demo_1_well_known_tsap()
        time.sleep(1)
        demo_2_portmapper()
        time.sleep(1)
        demo_3_inetd()
        time.sleep(1)
        demo_4_full_scenario_from_text()
        time.sleep(1)
        demo_5_comparison()
    elif choice == "0":
        print("Exit.")
        return
    else:
        print("Invalid choice.")
    
    print("\n" + "=" * 60)
    print("Demonstration completed.")


if __name__ == "__main__":
    main()