import network
import random
import requests
import threading

class Packet:
    def __init__(self, source_ip, dest_ip, size, data):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.size = size
        self.data = data
        self.timestamp = time.time()

    def __str__(self):
        return f"Packet from {self.source_ip} to {self.dest_ip} | Size: {self.size} bytes | Data: {self.data}"

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.sniffing = True

    def capture_packet(self, packet):
        if self.sniffing:
            self.packets.append(packet)
            print(f"Packet captured: {packet}")
            if len(self.packets) > 5:
                self.analyze_traffic()

    def analyze_traffic(self):
        print("\nAnalyzing network traffic...\n")
        for packet in self.packets:
            if 'attack' in packet.data:
                print(f"Warning: Suspicious packet detected! {packet}")
            else:
                print(f"Normal packet: {packet}")
        print("\nTraffic analysis complete.\n")

class TrafficGenerator:
    def __init__(self):
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'DNS']
        self.ip_range = ['192.168.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1']
        self.sniffer = PacketSniffer()

    def generate_packet(self):
        src_ip = random.choice(self.ip_range)
        dest_ip = random.choice(self.ip_range)
        size = random.randint(50, 1500)
        data = random.choice(self.protocols) + ' packet'
        packet = Packet(src_ip, dest_ip, size, data)
        self.sniffer.capture_packet(packet)

    def start_traffic(self):
        while True:
            self.generate_packet()
            time.sleep(random.uniform(0.1, 2.0))


class SimpleEncryptor:
    def encrypt(self, data):
        encrypted = ''.join(chr(ord(c) + 3) for c in data)
        return encrypted

    def decrypt(self, encrypted_data):
        decrypted = ''.join(chr(ord(c) - 3) for c in encrypted_data)
        return decrypted

class EncryptionHandler:
    def __init__(self):
        self.encryptor = SimpleEncryptor()

    def simulate_encryption_process(self, packet):
        print(f"Encrypting packet data: {packet.data}")
        encrypted_data = self.encryptor.encrypt(packet.data)
        print(f"Encrypted data: {encrypted_data}")
        packet.data = encrypted_data

    def simulate_decryption_process(self, packet):
        print(f"Decrypting packet data: {packet.data}")
        decrypted_data = self.encryptor.decrypt(packet.data)
        print(f"Decrypted data: {decrypted_data}")
        packet.data = decrypted_data

class IntrusionDetectionSystem:
    def __init__(self):
        self.alerts = []

    def generate_alert(self, packet):
        alert = f"ALERT: Potential attack detected in packet from {packet.source_ip} to {packet.dest_ip}"
        self.alerts.append(alert)
        print(f"Security Alert: {alert}")

    def monitor_traffic(self, sniffer):
        while True:
            if len(sniffer.packets) > 0:
                last_packet = sniffer.packets[-1]
                if 'attack' in last_packet.data:
                    self.generate_alert(last_packet)
            time.sleep(1)

class Firewall:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip):
        self.blocked_ips.add(ip)
        print(f"Firewall: Blocked IP {ip}")

    def is_blocked(self, ip):
        return ip in self.blocked_ips

class NetworkMonitor:
    def __init__(self):
        self.traffic_gen = TrafficGenerator()
        self.encryption_handler = EncryptionHandler()
        self.traffic_monitor = threading.Thread(target=self.traffic_gen.start_traffic)
        self.id_system = IntrusionDetectionSystem()
        self.firewall = Firewall()

    def start_monitoring(self):
        self.traffic_monitor.start()
        self.id_system.monitor_traffic(self.traffic_gen.sniffer)

    def block_attack(self, packet):
        print(f"Blocking attack from {packet.source_ip}")
        self.firewall.block_ip(packet.source_ip)

    def simulate_attack(self):
        while True:
            if random.random() < 0.1:
                packet = Packet("192.168.0.1", "10.0.0.2", 1024, "attack data")
                self.traffic_gen.sniffer.capture_packet(packet)
                self.block_attack(packet)
            time.sleep(2)
if __name__ == "__main__":
    network_monitor = NetworkMonitor()
    network_monitor.start_monitoring()
    attack_thread = threading.Thread(target=network_monitor.simulate_attack)
    attack_thread.start()

class Packet:
    def __init__(self, source_ip, dest_ip, size, data):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.size = size
        self.data = data
        self.timestamp = time.time()

    def __str__(self):
        return (f"[{time.strftime('%H:%M:%S', time.localtime(self.timestamp))}] "
                f"Packet from {self.source_ip} to {self.dest_ip} | Size: {self.size} bytes | Data: {self.data}")

class PacketSniffer:
    def __init__(self):
        self.packets = []
        self.sniffing = True
        self.log = []

    def capture_packet(self, packet):
        if self.sniffing:
            self.packets.append(packet)
            log_entry = f"Captured: {packet}"
            self.log.append(log_entry)
            print(log_entry)
            if len(self.packets) >= 5:
                self.analyze_traffic()

    def analyze_traffic(self):
        print("\n--- Traffic Analysis ---")
        for packet in self.packets[-5:]:
            if 'attack' in packet.data:
                print(f"** Suspicious Packet Detected **: {packet}")
            else:
                print(f"Normal Packet: {packet}")
        print("--- End of Analysis ---\n")

    def save_logs(self):
        with open("network_logs.txt", "w") as f:
            for entry in self.log:
                f.write(entry + "\n")
        print("[Sniffer] Logs saved to 'network_logs.txt'.")

class TrafficGenerator:
    def __init__(self, sniffer):
        self.protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'DNS']
        self.ip_range = ['192.168.0.1', '192.168.1.1', '10.0.0.1', '172.16.0.1']
        self.sniffer = sniffer

    def generate_packet(self):
        src_ip = random.choice(self.ip_range)
        dest_ip = random.choice(self.ip_range)
        size = random.randint(50, 1500)
        data = random.choice(self.protocols) + ' packet'
        packet = Packet(src_ip, dest_ip, size, data)
        self.sniffer.capture_packet(packet)

    def start_traffic(self):
        while True:
            self.generate_packet()
            time.sleep(random.uniform(0.1, 1.0))

class SimpleEncryptor:
    def encrypt(self, data):
        encrypted = ''.join(chr(ord(c) + 3) for c in data)
        return encrypted

    def decrypt(self, encrypted_data):
        decrypted = ''.join(chr(ord(c) - 3) for c in encrypted_data)
        return decrypted

class EncryptionHandler:
    def __init__(self):
        self.encryptor = SimpleEncryptor()

    def simulate_encryption(self, packet):
        print(f"[Encryption] Encrypting packet data: {packet.data}")
        encrypted_data = self.encryptor.encrypt(packet.data)
        packet.data = encrypted_data
        print(f"[Encryption] Result: {encrypted_data}")

    def simulate_decryption(self, packet):
        print(f"[Decryption] Decrypting packet data: {packet.data}")
        decrypted_data = self.encryptor.decrypt(packet.data)
        packet.data = decrypted_data
        print(f"[Decryption] Result: {decrypted_data}")

class IntrusionDetectionSystem:
    def __init__(self):
        self.alerts = []

    def monitor(self, sniffer):
        while True:
            for packet in sniffer.packets:
                if 'attack' in packet.data and packet not in self.alerts:
                    self.generate_alert(packet)
            time.sleep(1)

    def generate_alert(self, packet):
        alert = f"ALERT: Potential attack detected in packet from {packet.source_ip} to {packet.dest_ip}"
        self.alerts.append(alert)
        print(alert)

    def show_alerts(self):
        print("\n--- Active Alerts ---")
        for alert in self.alerts:
            print(alert)
        print("--- End of Alerts ---\n")

class Firewall:
    def __init__(self):
        self.blocked_ips = set()

    def block_ip(self, ip):
        if ip not in self.blocked_ips:
            self.blocked_ips.add(ip)
            print(f"[Firewall] Blocked IP: {ip}")

    def is_blocked(self, ip):
        return ip in self.blocked_ips

class NetworkMonitor:
    def __init__(self):
        self.sniffer = PacketSniffer()
        self.traffic_generator = TrafficGenerator(self.sniffer)
        self.encryption_handler = EncryptionHandler()
        self.ids = IntrusionDetectionSystem()
        self.firewall = Firewall()

    def start(self):
        threading.Thread(target=self.traffic_generator.start_traffic, daemon=True).start()
        threading.Thread(target=self.ids.monitor, args=(self.sniffer,), daemon=True).start()
        threading.Thread(target=self.simulate_security_responses, daemon=True).start()

    def simulate_security_responses(self):
        while True:
            if self.sniffer.packets:
                packet = random.choice(self.sniffer.packets)
                if 'attack' in packet.data:
                    self.firewall.block_ip(packet.source_ip)
                else:
                    self.encryption_handler.simulate_encryption(packet)
                    self.encryption_handler.simulate_decryption(packet)
            time.sleep(2)

def generate_fake_logs():
    print("\nGenerating historical logs...")
    log_lines = []
    for _ in range(100):
        src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dest_ip = f"10.0.{random.randint(0, 255)}.{random.randint(0, 255)}"
        size = random.randint(40, 1500)
        log_lines.append(f"[LOG] {src_ip} -> {dest_ip} | {size} bytes")
    with open("historical_logs.txt", "w") as file:
        file.write("\n".join(log_lines))
    print("Historical logs saved to 'historical_logs.txt'.\n")

if __name__ == "__main__":
    print("Starting Network Monitor...\n")
    network_monitor = NetworkMonitor()
    network_monitor.start()

    threading.Thread(target=generate_fake_logs, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down Network Monitor...")
def generate_detailed_logs():
    print("\nGenerating detailed logs...")
    log_entries = []
    severities = ["INFO", "WARNING", "CRITICAL"]
    for _ in range(300):  # Generate 300 lines for larger files
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        severity = random.choice(severities)
        src_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dest_ip = f"10.0.{random.randint(0, 255)}.{random.randint(0, 255)}"
        message = f"{severity}: {src_ip} -> {dest_ip} | {random.randint(40, 1500)} bytes"
        log_entries.append(f"[{timestamp}] {message}")
    with open("detailed_logs.txt", "w") as file:
        file.write("\n".join(log_entries))
    print("Detailed logs saved to 'detailed_logs.txt'.\n")

from colorama import Fore, Style

def color_log(message, level="info"):
    if level == "info":
        print(Fore.BLUE + message + Style.RESET_ALL)
    elif level == "warning":
        print(Fore.YELLOW + message + Style.RESET_ALL)
    elif level == "critical":
        print(Fore.RED + message + Style.RESET_ALL)

def interactive_console(monitor):
    print("\n[Console] Type 'help' for a list of commands.")
    while True:
        command = input("[Console]> ").strip()
        if command == "help":
            print("Commands:\n - alerts: Show active alerts\n - logs: Save current logs\n - exit: Exit system")
        elif command == "alerts":
            monitor.ids.show_alerts()
        elif command == "logs":
            monitor.sniffer.save_logs()
        elif command == "exit":
            print("[Console] Exiting...")
            break
        else:
            print("[Console] Unknown command. Type 'help' for a list of commands.")

class Packet:
    def __init__(self, source_ip, dest_ip, size, data):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.size = size
        self.data = data
        self.headers = {
            "protocol": random.choice(["TCP", "UDP", "HTTP"]),
            "ttl": random.randint(30, 120),
            "flags": random.choice(["SYN", "ACK", "FIN", "RST"]),
        }
        self.timestamp = time.time()

    def __str__(self):
        return (f"[{time.strftime('%H:%M:%S', time.localtime(self.timestamp))}] "
                f"Packet from {self.source_ip} to {self.dest_ip} | "
                f"Size: {self.size} bytes | Data: {self.data} | Headers: {self.headers}")

class NetworkMonitor:
    def __init__(self):
        self.sniffer = PacketSniffer()
        self.traffic_generator = TrafficGenerator(self.sniffer)
        self.encryption_handler = EncryptionHandler()
        self.ids = IntrusionDetectionSystem()
        self.firewall = Firewall()
        self.threat_database = ThreatDatabase()

    def simulate_security_responses(self):
        while True:
            if self.sniffer.packets:
                packet = random.choice(self.sniffer.packets)
                threat = self.threat_database.check_packet(packet)
                if threat:
                    print(f"[Threat Detected] {threat} in packet: {packet}")
                    self.firewall.block_ip(packet.source_ip)
                elif 'attack' in packet.data:
                    self.firewall.block_ip(packet.source_ip)
                else:
                    self.encryption_handler.simulate_encryption(packet)
                    self.encryption_handler.simulate_decryption(packet)
            time.sleep(2)

class ThreatDatabase:
    def __init__(self):
        self.threats = {
            "192.168.100.5": "DDoS Botnet",
            "10.0.50.77": "Ransomware Server",
            "attack": "Generic Attack Signature",
        }

    def check_packet(self, packet):
        for threat, description in self.threats.items():
            if threat in packet.source_ip or threat in packet.data:
                return description
        return None

# --- End Of Code ---
