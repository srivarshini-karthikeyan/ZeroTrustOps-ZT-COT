import os
import sys
import time
import json
import random
import socket
import hashlib
import threading
import subprocess
import ipaddress
from datetime import datetime
from getpass import getpass
import re
import uuid
import platform
import colorama
from colorama import Fore, Back, Style

# Initialize colorama
colorama.init(autoreset=True)

# File to store data
DATA_FILE = "cyber_sim_data.json"

# Default data structure
DEFAULT_DATA = {
    "accounts": {
        "admin": {"password": "admin123", "mfa_secret": "123456", "role": "admin"},
        "user": {"password": "user123", "mfa_secret": "654321", "role": "user"},
        "soc": {"password": "soc123", "mfa_secret": "246810", "role": "soc_analyst"}
    },
    "firewall_rules": [
        {"id": 1, "source": "192.168.1.0/24", "destination": "ANY", "port": "80,443", "action": "ALLOW"},
        {"id": 2, "source": "ANY", "destination": "192.168.1.100", "port": "22", "action": "DENY"},
    ],
    "known_mac_addresses": {},
    "file_hashes": {},
    "threat_logs": [],
    "clipboard_history": []
}

# Global variables
current_user = None
scanning = False
sniffing = False
monitoring = False
honeypot_running = False
file_watcher_running = False
hash_checker_running = False
log_visualizer_running = False
insider_tracker_running = False
stop_threads = False

# Try to import optional modules
try:
    import psutil
except ImportError:
    subprocess.call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

try:
    import pyperclip
except ImportError:
    subprocess.call([sys.executable, "-m", "pip", "install", "pyperclip"])
    import pyperclip

# Function to handle data
def load_data():
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as file:
                return json.load(file)
        else:
            save_data(DEFAULT_DATA)
            return DEFAULT_DATA
    except Exception as e:
        print(f"{Fore.RED}Error loading data: {e}")
        return DEFAULT_DATA

def save_data(data):
    try:
        with open(DATA_FILE, 'w') as file:
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"{Fore.RED}Error saving data: {e}")

def log_threat(threat_type, details, severity=None):
    data = load_data()
    if not severity:
        severity = random.choice(["Low", "Medium", "High", "Critical"])
    
    threat = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": threat_type,
        "details": details,
        "severity": severity
    }
    data["threat_logs"].append(threat)
    
    # Keep only the last 100 logs
    if len(data["threat_logs"]) > 100:
        data["threat_logs"] = data["threat_logs"][-100:]
    
    save_data(data)
    return threat

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"{Fore.CYAN}║ {Fore.RED}Z{Fore.GREEN}E{Fore.BLUE}R{Fore.YELLOW}O {Fore.MAGENTA}T{Fore.CYAN}R{Fore.WHITE}U{Fore.RED}S{Fore.GREEN}T {Fore.BLUE}C{Fore.YELLOW}Y{Fore.MAGENTA}B{Fore.CYAN}E{Fore.WHITE}R{Fore.RED}S{Fore.GREEN}E{Fore.BLUE}C{Fore.YELLOW}U{Fore.MAGENTA}R{Fore.CYAN}I{Fore.WHITE}T{Fore.RED}Y {Fore.GREEN}T{Fore.BLUE}O{Fore.YELLOW}O{Fore.MAGENTA}L{Fore.CYAN}K{Fore.WHITE}I{Fore.RED}T       {Fore.CYAN}║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
    print(f"{Fore.YELLOW}[*] Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.YELLOW}[*] System: {platform.system()} {platform.release()}")
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        print(f"{Fore.YELLOW}[*] Host: {hostname} ({ip_address})")
    except:
        print(f"{Fore.YELLOW}[*] Host: Unable to determine")
    print(f"{Fore.YELLOW}[*] Zero Trust Framework Active{Fore.RESET}")
    print()

def get_interfaces():
    interfaces = {}
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        interfaces["default"] = ip_address
        
        # Get additional interfaces if psutil is available
        if 'psutil' in sys.modules:
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                        interfaces[iface] = addr.address
    except:
        interfaces["eth0"] = "192.168.1.100"  # Fallback
    
    return interfaces

# Main functionality implementations
def mfa_bruteforce():
    data = load_data()
    accounts = list(data["accounts"].keys())
    
    print(f"{Fore.YELLOW}[*] Available accounts: {', '.join(accounts)}")
    account = input(f"{Fore.GREEN}[+] Enter account name to bruteforce: ")
    
    if account not in data["accounts"]:
        print(f"{Fore.RED}[!] Account not found!")
        return
    
    print(f"{Fore.YELLOW}[*] Starting MFA bruteforce for {account}...")
    print(f"{Fore.YELLOW}[*] Using intelligent brute force algorithm")
    
    correct_mfa = data["accounts"][account]["mfa_secret"]
    attempt_count = 0
    max_attempts = random.randint(5, 15)
    
    for i in range(max_attempts):
        attempt_count += 1
        
        if i > max_attempts * 0.7:
            test_mfa = ""
            for j in range(len(correct_mfa)):
                if random.random() < 0.7:
                    test_mfa += correct_mfa[j]
                else:
                    test_mfa += str(random.randint(0, 9))
        else:
            test_mfa = ''.join([str(random.randint(0, 9)) for _ in range(len(correct_mfa))])
        
        print(f"{Fore.CYAN}[*] Attempt {attempt_count}: Testing code {test_mfa[:2]}{'*' * (len(test_mfa)-2)}", end="")
        sys.stdout.flush()
        
        time.sleep(random.uniform(0.2, 0.5))
        log_threat("MFA Bruteforce", f"Attempt on account '{account}' with code {test_mfa[:2]}**...")
        
        if test_mfa == correct_mfa or i == max_attempts - 1:
            print(f"\r{Fore.GREEN}[+] SUCCESS! MFA code found: {correct_mfa}")
            print(f"{Fore.GREEN}[+] Account {account} compromised after {attempt_count} attempts")
            log_threat("MFA Bruteforce", f"SUCCESS: Account '{account}' compromised", "Critical")
            break
        else:
            print(f"\r{Fore.RED}[!] Failed with code {test_mfa[:2]}{'*' * (len(test_mfa)-2)}")
            
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def scan_ports(target_ip=None):
    global scanning, stop_threads
    scanning = True
    
    if not target_ip:
        target_ip = input(f"{Fore.GREEN}[+] Enter target IP to scan: ")
    
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        print(f"{Fore.RED}[!] Invalid IP address")
        scanning = False
        return
    
    print(f"{Fore.YELLOW}[*] Starting port scan on {target_ip}")
    print(f"{Fore.YELLOW}[*] Scanning common ports...")
    
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "MS-RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
        5900: "VNC", 8080: "HTTP-Proxy"
    }
    
    found_ports = []
    total_ports = len(common_ports)
    
    count = 0
    for port, service in common_ports.items():
        if stop_threads:
            break
            
        count += 1
        print(f"\r{Fore.YELLOW}[*] Progress: {count}/{total_ports} ports checked", end="")
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target_ip, port))
            s.close()
            
            if result == 0:
                found_ports.append((port, service))
                print(f"\r{Fore.GREEN}[+] Port {port} ({service}) is OPEN{' ' * 30}")
                log_threat("Port Scan", f"Open port found on {target_ip}: {port}/{service}")
                
        except socket.error:
            pass
            
        time.sleep(0.1)
    
    print(f"\r{Fore.YELLOW}[*] Scan completed. {len(found_ports)} open ports found.{' ' * 30}")
    
    if found_ports:
        print(f"\n{Fore.GREEN}[+] Open ports summary:")
        for port, service in found_ports:
            print(f"{Fore.GREEN}[+] {port}/TCP - {service}")
    else:
        print(f"\n{Fore.YELLOW}[*] No open ports found on {target_ip}")
        
    scanning = False
    stop_threads = False
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def packet_sniffer():
    global sniffing, stop_threads
    sniffing = True
    
    interfaces = get_interfaces()
    
    if not interfaces:
        print(f"{Fore.RED}[!] No network interfaces found")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")
        return
        
    print(f"{Fore.YELLOW}[*] Available network interfaces:")
    for idx, (iface, ip) in enumerate(interfaces.items(), 1):
        print(f"{Fore.GREEN}[{idx}] {iface} - {ip}")
    
    try:
        choice = int(input(f"{Fore.YELLOW}[*] Select interface (number): "))
        if choice < 1 or choice > len(interfaces):
            print(f"{Fore.RED}[!] Invalid choice")
            return
            
        iface = list(interfaces.keys())[choice-1]
    except ValueError:
        print(f"{Fore.RED}[!] Invalid input")
        return
        
    print(f"{Fore.YELLOW}[*] Starting packet sniffer on {iface} ({interfaces[iface]})")
    print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop sniffing")
    print(f"{Fore.YELLOW}[*] Capturing packets in real-time...\n")
    
    start_time = time.time()
    packet_count = 0
    protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    
    try:
        while not stop_threads and time.time() - start_time < 15:  # Run for 15 seconds max
            packet_count += 1
            
            # Simulate packet capture
            proto = random.choice(["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP", "Other"])
            protocols[proto] += 1
            
            # Random source and destination IPs
            src_ip = f"192.168.1.{random.randint(1, 254)}"
            dst_ip = f"192.168.1.{random.randint(1, 254)}"
            
            # Random ports for TCP/UDP
            if proto in ["TCP", "UDP"]:
                src_port = random.randint(1024, 65535)
                dst_port = random.choice([80, 443, 22, 53, 8080, 3389])
                app_proto = "HTTP" if dst_port == 80 else "HTTPS" if dst_port == 443 else "SSH" if dst_port == 22 else "DNS" if dst_port == 53 else f"{proto}"
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.CYAN}[{timestamp}] {Fore.GREEN}{proto}/{app_proto}: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
                # Simulate finding credentials
                if random.random() < 0.05:  # 5% chance
                    credentials = f"username=admin&password={''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))}"
                    print(f"{Fore.RED}[!] Possible credentials in packet: {credentials}")
                    log_threat("Packet Sniffing", f"Possible credentials detected: {credentials}", "High")
            else:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.CYAN}[{timestamp}] {Fore.BLUE}{proto}: {src_ip} -> {dst_ip}")
            
            time.sleep(0.2)
            
    except KeyboardInterrupt:
        pass
    finally:
        sniffing = False
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Packet sniffing stopped")
        print(f"{Fore.GREEN}[+] Summary: {packet_count} packets captured")
        for proto, count in protocols.items():
            print(f"{Fore.GREEN}[+] {proto}: {count} packets")
        log_threat("Network Monitoring", f"Packet sniffing performed", "Low")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def mac_spoof_detector():
    global monitoring, stop_threads
    monitoring = True
    
    print(f"{Fore.YELLOW}[*] Scanning for MAC addresses on local network...")
    
    # Get the actual network adapter info from the system
    macs = {}
    try:
        if 'psutil' in sys.modules:
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == getattr(socket, 'AF_LINK', -1):  # MAC addresses
                        mac = addr.address
                        if mac and not mac.startswith('00:00:00'):
                            macs[mac] = iface
                            print(f"{Fore.GREEN}[+] Found interface {iface} with MAC {mac}")
    except:
        pass
    
    # Add some simulated devices too
    sim_macs = {
        "00:11:22:33:44:55": "Router",
        "aa:bb:cc:dd:ee:ff": "Admin Laptop",
        "11:22:33:44:55:66": "User Workstation"
    }
    for mac, device in sim_macs.items():
        if mac not in macs:
            macs[mac] = device
            print(f"{Fore.GREEN}[+] Found device {device} with MAC {mac}")
    
    data = load_data()
    
    # Compare with known MACs
    print(f"\n{Fore.YELLOW}[*] Analyzing for potential MAC spoofing...")
    
    # Update known MACs if empty
    if not data["known_mac_addresses"]:
        print(f"{Fore.YELLOW}[*] No known MAC addresses in database, adding current ones as trusted...")
        data["known_mac_addresses"] = {mac: device for mac, device in macs.items()}
        save_data(data)
    
    # Check for unknown MACs
    unknown_macs = []
    for mac, device in macs.items():
        if mac not in data["known_mac_addresses"]:
            unknown_macs.append((mac, device))
            print(f"{Fore.RED}[!] Unknown MAC detected: {mac} ({device})")
            log_threat("MAC Spoofing", f"Unknown MAC address detected: {mac}", "High")
    
    # Add a simulated spoofed MAC
    spoofed_mac = "de:ad:be:ef:ca:fe"
    if random.random() < 0.7:  # 70% chance
        print(f"{Fore.RED}[!] ALERT: Potential spoofed MAC address: {spoofed_mac}")
        print(f"{Fore.RED}[!] This MAC address is showing unusual behavior - possible spoofing attack!")
        log_threat("MAC Spoofing", f"Potential spoofed MAC detected: {spoofed_mac}", "Critical")
    
    if not unknown_macs and random.random() > 0.7:
        print(f"{Fore.GREEN}[+] No unknown MAC addresses detected")
    
    monitoring = False
    input(f"\n{Fore.YELLOW}[*] Press Enter to continue...")

def soc_dashboard():
    global stop_threads
    stop_threads = False
    
    # Function to get real system metrics
    def get_system_metrics():
        metrics = {}
        try:
            if 'psutil' in sys.modules:
                # CPU usage
                metrics["cpu"] = psutil.cpu_percent(interval=0.1)
                
                # Memory usage
                mem = psutil.virtual_memory()
                metrics["memory"] = mem.percent
                
                # Disk usage
                disk = psutil.disk_usage('/')
                metrics["disk"] = disk.percent
                
                # Network connections
                metrics["connections"] = len(psutil.net_connections())
            else:
                raise ImportError("psutil not available")
        except:
            # Generate random metrics if real ones aren't available
            metrics["cpu"] = random.uniform(20, 85)
            metrics["memory"] = random.uniform(30, 90)
            metrics["disk"] = random.uniform(40, 75)
            metrics["connections"] = random.randint(10, 150)
        
        return metrics
    
    # Generate random attack data
    def generate_attack_data():
        attack_types = ["Brute Force", "SQL Injection", "XSS", "DDOS", "Data Exfiltration"]
        sources = ["45.227.253." + str(random.randint(1, 254)),
                   "103.102.166." + str(random.randint(1, 254)),
                   "185.156.73." + str(random.randint(1, 254)),
                   "192.168.1." + str(random.randint(1, 254))]
        
        return {
            "type": random.choice(attack_types),
            "source": random.choice(sources),
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "severity": random.choice(["Low", "Medium", "High", "Critical"])
        }
    
    # Load existing threats
    data = load_data()
    threats = data["threat_logs"][-10:] if data["threat_logs"] else []
    
    # Add some real-time generated threats if needed
    if len(threats) < 5:
        for _ in range(5 - len(threats)):
            attack = generate_attack_data()
            threats.append({
                "timestamp": attack["timestamp"],
                "type": attack["type"],
                "details": f"Attack from {attack['source']}",
                "severity": attack["severity"]
            })
    
    # Dashboard loop
    refresh_interval = 1.0  # seconds
    start_time = datetime.now()
    iteration = 0
    
    try:
        while not stop_threads and iteration < 20:  # Run for 20 iterations
            clear_screen()
            current_time = datetime.now()
            uptime = (current_time - start_time).seconds
            
            # Get system metrics
            metrics = get_system_metrics()
            
            # Header
            print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
            print(f"{Fore.CYAN}║ {Fore.YELLOW}ZERO TRUST SECURITY OPERATIONS CENTER - REAL-TIME DASHBOARD{' ' * 26}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Current Time: {current_time.strftime('%Y-%m-%d %H:%M:%S')} | Dashboard Uptime: {uptime}s{' ' * 10}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            # System metrics visualization
            cpu_bar = "█" * int(metrics["cpu"] / 5)
            mem_bar = "█" * int(metrics["memory"] / 5)
            disk_bar = "█" * int(metrics["disk"] / 5)
            
            cpu_color = Fore.GREEN if metrics["cpu"] < 70 else Fore.YELLOW if metrics["cpu"] < 90 else Fore.RED
            mem_color = Fore.GREEN if metrics["memory"] < 70 else Fore.YELLOW if metrics["memory"] < 90 else Fore.RED
            disk_color = Fore.GREEN if metrics["disk"] < 70 else Fore.YELLOW if metrics["disk"] < 90 else Fore.RED
            conn_color = Fore.GREEN if metrics["connections"] < 100 else Fore.YELLOW if metrics["connections"] < 200 else Fore.RED
            
            print(f"{Fore.CYAN}║ {Fore.WHITE}System Metrics:{' ' * 62}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}CPU Usage:  {cpu_color}{metrics['cpu']:3.1f}% {cpu_bar}{' ' * (20 - len(cpu_bar))}{' ' * 24}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Memory:     {mem_color}{metrics['memory']:3.1f}% {mem_bar}{' ' * (20 - len(mem_bar))}{' ' * 24}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Disk:       {disk_color}{metrics['disk']:3.1f}% {disk_bar}{' ' * (20 - len(disk_bar))}{' ' * 24}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Connections: {conn_color}{metrics['connections']}{' ' * 57}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            # Threat summary
            severity_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
            for threat in threats:
                severity_counts[threat["severity"]] += 1
            
            print(f"{Fore.CYAN}║ {Fore.WHITE}Threat Summary:{' ' * 61}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.GREEN}Low: {severity_counts['Low']:2d} | {Fore.YELLOW}Medium: {severity_counts['Medium']:2d} | {Fore.RED}High: {severity_counts['High']:2d} | {Fore.MAGENTA}Critical: {severity_counts['Critical']:2d}{' ' * 30}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            
            # Recent threats
            print(f"{Fore.CYAN}║ {Fore.WHITE}Recent Threats:{' ' * 62}{Fore.CYAN}║")
            
            # Add a new threat every few iterations
            iteration += 1
            if iteration % 3 == 0:
                attack = generate_attack_data()
                new_threat = {
                    "timestamp": attack["timestamp"],
                    "type": attack["type"],
                    "details": f"Attack from {attack['source']}",
                    "severity": attack["severity"]
                }
                threats.append(new_threat)
                threats = threats[-10:]  # Keep only the last 10
                log_threat(attack["type"], f"Attack from {attack['source']}", attack["severity"])
            
            # Show last 5 threats
            for i, threat in enumerate(threats[-5:]):
                severity_color = (Fore.GREEN if threat["severity"] == "Low" else
                                 Fore.YELLOW if threat["severity"] == "Medium" else
                                 Fore.RED if threat["severity"] == "High" else
                                 Fore.MAGENTA)
                
                threat_info = threat["details"][:40]
                print(f"{Fore.CYAN}║ {severity_color}[{threat['severity']}] {threat['timestamp']} - {threat['type']}: {threat_info}{' ' * (13 - len(threat_info))}{Fore.CYAN}║")
            
            # Fill empty lines if less than 5 threats
            for _ in range(5 - min(5, len(threats))):
                print(f"{Fore.CYAN}║{' ' * 74}{Fore.CYAN}║")
            
            print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
            print(f"{Fore.CYAN}║ {Fore.WHITE}Zero Trust Status: {Fore.GREEN}ACTIVE{' ' * 54}{Fore.CYAN}║")
            print(f"{Fore.CYAN}║ {Fore.WHITE}MFA Enforcement: {Fore.GREEN}ENABLED{' ' * 54}{Fore.CYAN}║")
            print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
            
            print(f"\n{Fore.YELLOW}[*] Press Ctrl+C to exit dashboard")
            
            time.sleep(refresh_interval)
    except KeyboardInterrupt:
        pass
    finally:
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Dashboard stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def ransomware_file_watcher():
    """Simulates a ransomware file watcher that monitors for suspicious file operations"""
    global file_watcher_running, stop_threads
    
    file_watcher_running = True
    stop_threads = False
    
    print(f"{Fore.YELLOW}[*] Starting Ransomware File Watcher...")
    print(f"{Fore.YELLOW}[*] Monitoring file system for encryption and suspicious activities")
    print(f"{Fore.YELLOW}[*] Press 'q' to stop monitoring\n")
    
    # Create a directory to monitor
    monitor_dir = os.path.join(os.getcwd(), "monitor_files")
    if not os.path.exists(monitor_dir):
        os.makedirs(monitor_dir)
        print(f"{Fore.GREEN}[+] Created monitoring directory: {monitor_dir}")
    
    # Sample file extensions that ransomware commonly targets
    target_extensions = ['.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', 
                        '.zip', '.rar', '.jpg', '.jpeg', '.png', '.txt', '.csv']
    
    # Suspicious ransomware extensions
    ransomware_extensions = ['.encrypt', '.crypto', '.locked', '.crypted', '.cry',
                           '.locked', '.wcry', '.wncry', '.crypt', '.WNCRY',
                           '.locky', '.zepto', '.cerber', '.cerber3', '.crypt']
    
    try:
        iteration = 0
        while not stop_threads:
            iteration += 1
            current_time = datetime.now().strftime("%H:%M:%S")
            
            # Simulate detection events every few iterations
            if iteration % 3 == 0:
                event_type = random.choice([
                    "Multiple file renames",
                    "Suspicious extension change",
                    "High disk I/O activity",
                    "Shadow copy deletion attempt",
                    "Mass file encryption",
                    "Ransomware note creation",
                    "BTC wallet address found in new file"
                ])
                
                affected_files = random.randint(1, 15)
                file_ext = random.choice(target_extensions)
                ransom_ext = random.choice(ransomware_extensions)
                
                # Change color based on severity
                if affected_files > 10:
                    color = Fore.RED
                    severity = "Critical"
                elif affected_files > 5:
                    color = Fore.YELLOW
                    severity = "High"
                else:
                    color = Fore.CYAN
                    severity = "Medium"
                
                print(f"{color}[!] {current_time} - ALERT: {event_type}")
                print(f"{color}[!] {affected_files} files with {file_ext} extension affected")
                
                if "extension change" in event_type:
                    print(f"{color}[!] Files being renamed to {file_ext}{ransom_ext}")
                    
                if "encryption" in event_type:
                    print(f"{color}[!] Encryption pattern detected: {ransom_ext}")
                    print(f"{color}[!] CRITICAL: Possible ransomware '{random.choice(['WannaCry', 'Locky', 'Ryuk', 'REvil', 'DarkSide'])}' variant detected!")
                
                # Log the ransomware alert
                log_threat("Ransomware Activity", f"{event_type} - {affected_files} files affected", severity)
                    
            # Show scanning status in between alerts
            else:
                print(f"{Fore.GREEN}[+] {current_time} - Monitoring file system... No threats detected")
            
            # Check for key press
            if msvcrt_available():
                import msvcrt
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b'q':
                        break
            
            # Sleep with progress indicator
            for _ in range(10):
                if stop_threads:
                    break
                time.sleep(0.1)
                
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"{Fore.RED}[!] Error in ransomware file watcher: {e}")
    finally:
        file_watcher_running = False
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] Ransomware File Watcher stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def login_honeypot():
    """Create a honeypot that simulates an SSH server to catch login attempts"""
    global honeypot_running, stop_threads
    
    honeypot_running = True
    stop_threads = False
    
    print(f"{Fore.YELLOW}[*] Starting SSH Login Honeypot...")
    
    # Choose a port for the honeypot
    port = 2222  # Commonly used for SSH testing
    
    # Create a socket server
    server_socket = None
    
    def honeypot_thread():
        nonlocal server_socket
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', port))
            server_socket.settimeout(1.0)  # Set timeout for listening
            server_socket.listen(5)
            
            print(f"{Fore.GREEN}[+] SSH Honeypot started on port {port}")
            print(f"{Fore.YELLOW}[*] Waiting for connection attempts...")
            print(f"{Fore.YELLOW}[*] Press 'q' to stop the honeypot\n")
            
            attack_ips = [
                "45.227.253." + str(random.randint(1, 254)),
                "103.102.166." + str(random.randint(1, 254)),
                "185.156.73." + str(random.randint(1, 254)),
                "192.168.1." + str(random.randint(1, 254))
            ]
            
            iteration = 0
            while not stop_threads:
                try:
                    # Try to accept a connection
                    client_socket, address = server_socket.accept()
                    
                    # Got a connection!
                    timestamp = datetime.now().strftime("%H:%M:%S")
                    print(f"{Fore.RED}[!] {timestamp} - Connection attempt from {address[0]}:{address[1]}")
                    
                    # Send SSH banner
                    client_socket.send(b"SSH-2.0-OpenSSH_7.9p1 Ubuntu-10\r\n")
                    
                    # Wait for response
                    response = client_socket.recv(1024)
                    if response:
                        print(f"{Fore.YELLOW}[*] Received: {response.decode('utf-8', errors='ignore').strip()}")
                    
                    # Ask for username
                    client_socket.send(b"login as: ")
                    username = client_socket.recv(1024)
                    if username:
                        print(f"{Fore.RED}[!] Login attempt with username: {username.decode('utf-8', errors='ignore').strip()}")
                    
                    # Ask for password
                    client_socket.send(b"\r\nPassword: ")
                    password = client_socket.recv(1024)
                    if password:
                        password_str = password.decode('utf-8', errors='ignore').strip()
                        print(f"{Fore.RED}[!] Password attempt: {password_str}")
                        
                        # Log the attempt
                        details = f"SSH login attempt from {address[0]} - User: {username.decode('utf-8', errors='ignore').strip()}, Pass: {password_str}"
                        log_threat("SSH Brute Force", details, "High")
                    
                    # Send failure and disconnect
                    client_socket.send(b"\r\nAccess denied\r\n")
                    client_socket.close()
                    
                except socket.timeout:
                    # No real connection, simulate one every few iterations
                    iteration += 1
                    if iteration % 5 == 0:
                        attack_ip = random.choice(attack_ips)
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        print(f"{Fore.RED}[!] {timestamp} - Connection attempt from {attack_ip}:34218")
                        
                        # Generate random credentials
                        username = random.choice(["root", "admin", "user", "oracle", "postgres", "ubuntu", "test"])
                        password = random.choice(["password", "123456", "admin", "root123", "qwerty", "test", "p@ssw0rd"])
                        
                        print(f"{Fore.RED}[!] Login attempt with username: {username}")
                        print(f"{Fore.RED}[!] Password attempt: {password}")
                        
                        # Log the simulated attempt
                        details = f"SSH login attempt from {attack_ip} - User: {username}, Pass: {password}"
                        log_threat("SSH Brute Force", details, "High")
                        
                        # Show result
                        print(f"{Fore.YELLOW}[*] Access denied - Connection logged")
                    else:
                        # Show status message every few seconds
                        if iteration % 10 == 0:
                            timestamp = datetime.now().strftime("%H:%M:%S")
                            print(f"{Fore.GREEN}[+] {timestamp} - Honeypot running, no connection attempts...")
                
            # End of honeypot_thread
        except Exception as e:
            print(f"{Fore.RED}[!] Error in honeypot: {e}")
        finally:
            if server_socket:
                server_socket.close()
    
    # Start the honeypot thread
    honey_thread = threading.Thread(target=honeypot_thread)
    honey_thread.daemon = True
    honey_thread.start()
    
    # Wait for user to quit
    try:
        while honeypot_running and not stop_threads:
            if msvcrt_available():
                import msvcrt
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key == b'q':
                        stop_threads = True
                        break
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        honeypot_running = False
        stop_threads = True
        print(f"\n{Fore.YELLOW}[*] SSH Honeypot stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def file_hash_checker():
    """Monitor files for changes by tracking their hash values in real-time"""
    global hash_checker_running, stop_threads
    
    hash_checker_running = True
    stop_threads = False
    
    print(f"{Fore.YELLOW}[*] Starting Real-Time File Hash Checker...")
    
    # Get directory to monitor
    print(f"{Fore.YELLOW}[*] Enter directory to monitor (default: current directory):")
    monitor_dir = input(f"{Fore.GREEN}[+] > ").strip() or os.getcwd()
    
    if not os.path.exists(monitor_dir):
        print(f"{Fore.RED}[!] Directory doesn't exist")
        hash_checker_running = False
        return
        
    print(f"{Fore.GREEN}[+] Monitoring directory: {monitor_dir}")
    print(f"{Fore.YELLOW}[*] Calculating initial hashes, please wait...\n")
    
    # Load existing file hashes data
    data = load_data()
    file_hashes = data["file_hashes"]
    
    # Set for tracking files that have been hashed
    processed_files = set()
    
    # Calculate file hash
    def calculate_hash(file_path):
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as file:
                buf = file.read(65536)  # Read in 64k chunks
                while len(buf) > 0:
                    hasher.update(buf)
                    buf = file.read(65536)
            return hasher.hexdigest()
        except Exception as e:
            return f"Error: {str(e)}"
    
    # Scan initial files
    initial_files = {}
    for root, _, files in os.walk(monitor_dir):
        for file in files:
            if stop_threads:
                break
                
            file_path = os.path.join(root, file)
            try:
                # Skip large files
                if os.path.getsize(file_path) > 50000000:  # 50MB
                    continue
                
                hash_value = calculate_hash(file_path)
                initial_files[file_path] = hash_value
                processed_files.add(file_path)
                
                # Update global hash store if new
                rel_path = os.path.relpath(file_path, monitor_dir)
                if rel_path not in file_hashes:
                    file_hashes[rel_path] = {
                        "hash": hash_value,
                        "first_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "last_checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                
                # Print progress for every 10 files
                if len(processed_files) % 10 == 0:
                    print(f"{Fore.GREEN}[+] Processed {len(processed_files)} files...")
            except Exception as e:
                pass
    
    # Save updated hashes
    data["file_hashes"] = file_hashes
    save_data(data)
    
    print(f"{Fore.GREEN}[+] Initial scan complete: {len(processed_files)} files indexed")
    print(f"{Fore.YELLOW}[*] Starting continuous monitoring. Press 'q' to stop.\n")
    
    # List of suspicious file types to highlight
    suspicious_exts = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.jar', '.py']
    
    # Generate some simulated file changes for the demo
    def simulate_file_changes():
        nonlocal initial_files
        
        # Select a random file to simulate changes on
        if initial_files:
            file_path = random.choice(list(initial_files.keys()))
            
            # Different types of simulated events
            event_types = [
                "modified", "modified", "modified",  # Modified is most common
                "new", "deleted"
            ]
            event_type = random.choice(event_types)
            
            timestamp = datetime.now().strftime("%H:%M:%S")
            rel_path = os.path.relpath(file_path, monitor_dir)
            
            if event_type == "modified":
                old_hash = initial_files[file_path]
                new_hash = hashlib.sha256(str(random.random()).encode()).hexdigest()
                initial_files[file_path] = new_hash
                
                # Determine severity based on file type
                severity = "Medium"
                is_suspicious = False
                for ext in suspicious_exts:
                    if file_path.lower().endswith(ext):
                        severity = "High"
                        is_suspicious = True
                        break
                
                # Colorize output based on severity
                color = Fore.RED if is_suspicious else Fore.YELLOW
                
                print(f"{color}[!] {timestamp} - File changed: {rel_path}")
                print(f"{color}[!] Old hash: {old_hash[:16]}...")
                print(f"{color}[!] New hash: {new_hash[:16]}...")
                
                if is_suspicious:
                    print(f"{Fore.RED}[!] WARNING: Suspicious file type modified!")
                    
                # Log the event
                log_threat("File Integrity", f"File modified: {rel_path}", severity)
                
            elif event_type == "new":
                new_path = os.path.join(monitor_dir, f"new_file_{int(time.time())}.txt")
                new_hash = hashlib.sha256(str(random.random()).encode()).hexdigest()
                initial_files[new_path] = new_hash
                
                print(f"{Fore.CYAN}[*] {timestamp} - New file detected: {os.path.basename(new_path)}")
                print(f"{Fore.CYAN}[*] Hash: {new_hash[:16]}...")
                
                # Log the event
                log_threat("File Integrity", f"New file created: {os.path.basename(new_path)}", "Low")
                
            elif event_type == "deleted":
                print(f"{Fore.MAGENTA}[!] {timestamp} - File deleted: {rel_path}")
                initial_files.pop(file_path, None)
                
                # Log the event
                log_threat("File Integrity", f"File deleted: {rel_path}", "Medium")
    
    # Main monitoring loop
    try:
        iteration = 0
        while not stop_threads:
            iteration += 1
            
            # Sleep to reduce CPU usage, check for key press
            for _ in range(10):
                if stop_threads:
                    break
                time.sleep(0.1)
                
                # Check for 'q' key press
                if msvcrt_available():
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch()
                        if key == b'q':
                            stop_threads = True
                            break
            
            # Simulate a file change every few iterations
            if iteration % 5 == 0:
                simulate_file_changes()
            
            # Show activity message
            if iteration % 10 == 0:
                timestamp = datetime.now().strftime("%H:%M:%S")
                print(f"{Fore.GREEN}[+] {timestamp} - Monitoring files for changes... ({len(initial_files)} files)")
                
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"{Fore.RED}[!] Error in file hash checker: {e}")
    finally:
        hash_checker_running = False
        stop_threads = False
        print(f"\n{Fore.YELLOW}[*] File Hash Checker stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def firewall_simulator():
    """Simulate a firewall by managing and testing rules"""
    clear_screen()
    print_banner()
    
    # Load firewall rules
    data = load_data()
    rules = data["firewall_rules"]
    
    def display_rules():
        """Display all firewall rules in a formatted table"""
        print(f"\n{Fore.CYAN}╔════╦══════════════════╦══════════════════╦═══════════════════╦═══════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}ID{Fore.CYAN} ║ {Fore.YELLOW}Source{' ' * 10}{Fore.CYAN} ║ {Fore.YELLOW}Destination{' ' * 6}{Fore.CYAN} ║ {Fore.YELLOW}Port/Protocol{' ' * 5}{Fore.CYAN} ║ {Fore.YELLOW}Action{Fore.CYAN} ║")
        print(f"{Fore.CYAN}╠════╬══════════════════╬══════════════════╬═══════════════════╬═══════╣")
        
        for rule in rules:
            # Format source and destination fields
            source = rule.get("source", "ANY")
            if len(source) > 16:
                source = source[:13] + "..."
            
            destination = rule.get("destination", "ANY")
            if len(destination) > 16:
                destination = destination[:13] + "..."
            
            # Format ports field
            port = rule.get("port", "ANY")
            if len(str(port)) > 15:
                port = str(port)[:12] + "..."
            
            # Choose color based on action
            if rule.get("action", "").upper() == "ALLOW":
                action_color = Fore.GREEN
            elif rule.get("action", "").upper() == "DENY":
                action_color = Fore.RED
            else:
                action_color = Fore.YELLOW
                
            # Print rule
            print(f"{Fore.CYAN}║ {Fore.WHITE}{rule.get('id', 0):2d}{' ' * 2}{Fore.CYAN} ║ {Fore.WHITE}{source}{' ' * (16 - len(source))}{Fore.CYAN} ║ {Fore.WHITE}{destination}{' ' * (16 - len(destination))}{Fore.CYAN} ║ {Fore.WHITE}{port}{' ' * (17 - len(str(port)))}{Fore.CYAN} ║ {action_color}{rule.get('action', '').upper()}{' ' * (5 - len(rule.get('action', '')))}{Fore.CYAN} ║")
            
        print(f"{Fore.CYAN}╚════╩══════════════════╩══════════════════╩═══════════════════╩═══════╝")
    
    def add_rule():
        """Add a new firewall rule"""
        print(f"\n{Fore.YELLOW}[*] Add New Firewall Rule")
        
        # Generate new ID (one more than the highest existing ID)
        new_id = max([rule.get('id', 0) for rule in rules], default=0) + 1
        
        # Get source
        print(f"{Fore.GREEN}[+] Source IP/Network (enter 'ANY' for any source):")
        source = input(f"{Fore.GREEN}> ").strip()
        if not source:
            source = "ANY"
            
        # Validate IP/Network
        if source != "ANY":
            try:
                ipaddress.ip_network(source)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid IP or network format. Using 'ANY'")
                source = "ANY"
        
        # Get destination
        print(f"{Fore.GREEN}[+] Destination IP/Network (enter 'ANY' for any destination):")
        destination = input(f"{Fore.GREEN}> ").strip()
        if not destination:
            destination = "ANY"
            
        # Validate IP/Network
        if destination != "ANY":
            try:
                ipaddress.ip_network(destination)
            except ValueError:
                print(f"{Fore.RED}[!] Invalid IP or network format. Using 'ANY'")
                destination = "ANY"
        
        # Get port(s)
        print(f"{Fore.GREEN}[+] Port(s) (e.g., '80', '22-25', '80,443', or 'ANY'):")
        port = input(f"{Fore.GREEN}> ").strip()
        if not port:
            port = "ANY"
        
        # Get action
        print(f"{Fore.GREEN}[+] Action (ALLOW/DENY):")
        action = input(f"{Fore.GREEN}> ").strip().upper()
        if action not in ["ALLOW", "DENY"]:
            print(f"{Fore.RED}[!] Invalid action. Using 'DENY'")
            action = "DENY"
        
        # Create the rule
        new_rule = {
            "id": new_id,
            "source": source,
            "destination": destination,
            "port": port,
            "action": action
        }
        
        # Add to rules and save
        rules.append(new_rule)
        data["firewall_rules"] = rules
        save_data(data)
        
        print(f"{Fore.GREEN}[+] Rule added successfully!")
        
    def delete_rule():
        """Delete an existing firewall rule"""
        display_rules()
        
        print(f"\n{Fore.YELLOW}[*] Delete Firewall Rule")
        print(f"{Fore.GREEN}[+] Enter rule ID to delete:")
        
        try:
            rule_id = int(input(f"{Fore.GREEN}> ").strip())
        except ValueError:
            print(f"{Fore.RED}[!] Invalid ID")
            return
        
        # Find and delete the rule
        for i, rule in enumerate(rules):
            if rule.get("id") == rule_id:
                del rules[i]
                data["firewall_rules"] = rules
                save_data(data)
                print(f"{Fore.GREEN}[+] Rule {rule_id} deleted successfully!")
                return
        
        print(f"{Fore.RED}[!] Rule ID {rule_id} not found")
    
    def test_connection():
        """Test if a connection would be allowed by the firewall rules"""
        print(f"\n{Fore.YELLOW}[*] Test Connection Against Firewall Rules")
        
        # Get source IP
        print(f"{Fore.GREEN}[+] Source IP:")
        source_ip = input(f"{Fore.GREEN}> ").strip()
        if not source_ip:
            print(f"{Fore.RED}[!] Source IP required")
            return
            
        # Validate IP
        try:
            source_ip_obj = ipaddress.ip_address(source_ip)
        except ValueError:
            print(f"{Fore.RED}[!] Invalid IP address")
            return
        
        # Get destination IP
        print(f"{Fore.GREEN}[+] Destination IP:")
        dest_ip = input(f"{Fore.GREEN}> ").strip()
        if not dest_ip:
            print(f"{Fore.RED}[!] Destination IP required")
            return
            
        # Validate IP
        try:
            dest_ip_obj = ipaddress.ip_address(dest_ip)
        except ValueError:
            print(f"{Fore.RED}[!] Invalid IP address")
            return
        
        # Get port
        print(f"{Fore.GREEN}[+] Port:")
        try:
            port = int(input(f"{Fore.GREEN}> ").strip())
            if port < 1 or port > 65535:
                raise ValueError("Port out of range")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid port")
            return
        
        print(f"\n{Fore.YELLOW}[*] Testing connection: {source_ip} -> {dest_ip}:{port}")
        print(f"{Fore.YELLOW}[*] Evaluating firewall rules...")
        time.sleep(1)  # Simulate processing
        
        # Check rules in order
        matched_rule = None
        
        for rule in rules:
            # Check if rule matches
            source_match = False
            dest_match = False
            port_match = False
            
            # Check source match
            if rule.get("source") == "ANY":
                source_match = True
            else:
                try:
                    rule_network = ipaddress.ip_network(rule.get("source"))
                    source_match = source_ip_obj in rule_network
                except ValueError:
                    source_match = (source_ip == rule.get("source"))
            
            # Check destination match
            if rule.get("destination") == "ANY":
                dest_match = True
            else:
                try:
                    rule_network = ipaddress.ip_network(rule.get("destination"))
                    dest_match = dest_ip_obj in rule_network
                except ValueError:
                    dest_match = (dest_ip == rule.get("destination"))
            
            # Check port match
            if rule.get("port") == "ANY":
                port_match = True
            else:
                port_str = str(rule.get("port"))
                
                # Handle comma-separated ports
                if "," in port_str:
                    port_list = [p.strip() for p in port_str.split(",")]
                    port_match = str(port) in port_list
                # Handle port ranges
                elif "-" in port_str:
                    try:
                        start, end = map(int, port_str.split("-"))
                        port_match = start <= port <= end
                    except ValueError:
                        port_match = False
                # Single port
                else:
                    try:
                        port_match = (port == int(port_str))
                    except ValueError:
                        port_match = False
            
            # If all match, we found our rule
            if source_match and dest_match and port_match:
                matched_rule = rule
                break
                
        # Print result
        print("\n" + "=" * 50)
        if matched_rule:
            action = matched_rule.get("action", "").upper()
            if action == "ALLOW":
                print(f"{Fore.GREEN}[+] Connection ALLOWED by rule {matched_rule.get('id')}")
                print(f"{Fore.GREEN}[+] Rule details: {matched_rule}")
            else:
                print(f"{Fore.RED}[!] Connection BLOCKED by rule {matched_rule.get('id')}")
                print(f"{Fore.RED}[!] Rule details: {matched_rule}")
        else:
            # Default deny policy
            print(f"{Fore.RED}[!] No matching rule found. Using default policy: DENY")
            
        print("=" * 50)
        
        # Log the test
        action_result = "ALLOWED" if matched_rule and matched_rule.get("action").upper() == "ALLOW" else "BLOCKED"
        log_threat("Firewall Test", f"Connection test: {source_ip} -> {dest_ip}:{port} {action_result}")
    
    def simulate_traffic():
        """Simulate random traffic against the firewall"""
        print(f"\n{Fore.YELLOW}[*] Simulating Network Traffic")
        print(f"{Fore.YELLOW}[*] Press Enter to stop the simulation\n")
        
        # Generate random IPs
        def random_ip():
            return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Common services for realistic simulation
        services = {
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Alt"
        }
        
        # Start simulating traffic
        try:
            iteration = 0
            running = True
            while running:
                iteration += 1
                
                # Generate random traffic data
                src_ip = random_ip()
                dst_ip = random_ip()
                port = random.choice(list(services.keys()) + [random.randint(1024, 65535)])
                service = services.get(port, f"Port {port}")
                
                # Evaluate against firewall rules
                allowed = False
                matching_rule = None
                
                for rule in rules:
                    src_match = (rule.get("source") == "ANY")
                    dst_match = (rule.get("destination") == "ANY")
                    port_match = (rule.get("port") == "ANY")
                    
                    # Check for specific matches
                    if not src_match and rule.get("source") != "ANY":
                        try:
                            network = ipaddress.ip_network(rule.get("source"))
                            src_match = ipaddress.ip_address(src_ip) in network
                        except ValueError:
                            src_match = (src_ip == rule.get("source"))
                    
                    if not dst_match and rule.get("destination") != "ANY":
                        try:
                            network = ipaddress.ip_network(rule.get("destination"))
                            dst_match = ipaddress.ip_address(dst_ip) in network
                        except ValueError:
                            dst_match = (dst_ip == rule.get("destination"))
                    
                    if not port_match and rule.get("port") != "ANY":
                        port_str = str(rule.get("port"))
                        
                        if "," in port_str:
                            port_match = str(port) in [p.strip() for p in port_str.split(",")]
                        elif "-" in port_str:
                            try:
                                start, end = map(int, port_str.split("-"))
                                port_match = start <= port <= end
                            except ValueError:
                                port_match = False
                        else:
                            try:
                                port_match = (port == int(port_str))
                            except ValueError:
                                port_match = False
                    
                    # If all match, we've found our rule
                    if src_match and dst_match and port_match:
                        matching_rule = rule
                        allowed = (rule.get("action", "").upper() == "ALLOW")
                        break
                
                # Print the traffic and result
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if allowed:
                    print(f"{Fore.GREEN}[+] {timestamp} - ALLOWED: {src_ip} -> {dst_ip}:{port} ({service}) - Rule #{matching_rule.get('id')}")
                else:
                    rule_id = matching_rule.get('id') if matching_rule else "Default"
                    print(f"{Fore.RED}[!] {timestamp} - BLOCKED: {src_ip} -> {dst_ip}:{port} ({service}) - Rule #{rule_id}")
                
                # Randomly log some events
                if random.random() < 0.2:  # 20% chance to log
                    severity = "Low" if allowed else "Medium"
                    action = "allowed" if allowed else "blocked"
                    log_threat("Firewall Traffic", f"Connection {action}: {src_ip} -> {dst_ip}:{port}", severity)
                
                # Check if user wants to stop
                if msvcrt_available():
                    import msvcrt
                    if msvcrt.kbhit():
                        running = False
                
                # Add a small delay between events
                time.sleep(0.5)
                
        except KeyboardInterrupt:
            pass
        
        print(f"\n{Fore.YELLOW}[*] Traffic simulation ended")
    
    # Firewall simulator menu
    while True:
        clear_screen()
        print_banner()
        print(f"{Fore.CYAN}╔══════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}FIREWALL RULES SIMULATOR{' ' * 12}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.GREEN}1. View All Rules{' ' * 19}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}2. Add New Rule{' ' * 20}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}3. Delete Rule{' ' * 21}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}4. Test Connection{' ' * 18}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}5. Simulate Traffic{' ' * 17}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}0. Back to Main Menu{' ' * 16}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════╝")
        
        choice = input(f"\n{Fore.YELLOW}Enter your choice: ")
        
        if choice == '1':
            display_rules()
            input(f"\n{Fore.YELLOW}Press Enter to continue...")
        elif choice == '2':
            add_rule()
            input(f"\n{Fore.YELLOW}Press Enter to continue...")
        elif choice == '3':
            delete_rule()
            input(f"\n{Fore.YELLOW}Press Enter to continue...")
        elif choice == '4':
            test_connection()
            input(f"\n{Fore.YELLOW}Press Enter to continue...")
        elif choice == '5':
            simulate_traffic()
        elif choice == '0':
            break
        else:
            print(f"{Fore.RED}Invalid choice!")
            time.sleep(1)

def sms_dos_attack():
    """Simulate a DOS attack by sending spam messages to a phone number"""
    clear_screen()
    print_banner()
    
    print(f"{Fore.CYAN}╔══════════════════════════════════════╗")
    print(f"{Fore.CYAN}║ {Fore.RED}SMS BOMBING SIMULATOR{' ' * 15}{Fore.CYAN}║")
    print(f"{Fore.CYAN}╠══════════════════════════════════════╣")
    print(f"{Fore.CYAN}║ {Fore.YELLOW}This tool simulates SMS bombing{' ' * 6}{Fore.CYAN}║")
    print(f"{Fore.CYAN}║ {Fore.YELLOW}No actual messages are sent{' ' * 11}{Fore.CYAN}║")
    print(f"{Fore.CYAN}╚══════════════════════════════════════╝\n")
    
    # Get phone number
    phone = input(f"{Fore.GREEN}Enter target phone number: ")
    
    # Validate phone number format
    if not re.match(r'^\+?[\d\s\-\(\)]{7,20}$', phone):
        print(f"{Fore.RED}[!] Invalid phone number format")
        input(f"{Fore.YELLOW}Press Enter to continue...")
        return
    
    # Get number of messages
    try:
        count = int(input(f"{Fore.GREEN}Enter number of messages to send (10-100): "))
        if count < 1 or count > 100:
            raise ValueError("Count out of range")
    except ValueError:
        print(f"{Fore.RED}[!] Invalid count, using default of 20")
        count = 20
    
    # Sample spam messages
    spam_messages = [
        "Your account has been locked! Click here to verify: shady-link.co/verify",
        "URGENT: Your payment of $299.99 was processed. Call +1-555-SCAM to cancel",
        "You've WON a FREE iPhone 14! Claim now at free-iphone-notascam.com",
        "Your package delivery failed. Track here: track-notreal.co/redir?q=",
        "ALERT: Unusual activity detected on your account. Verify now: secure-phishing.net",
        "50% OFF all items today ONLY! Shop now: discount-malware.shop",
        "Your subscription will be charged $49.99 tomorrow. Cancel: sub-scam.biz/cancel",
        "Bank alert: Your card has been suspended. Reactivate: bank-fishing.info/unlock",
        "Your password was reset. If this wasn't you, click: pw-stealer.xyz/reset",
        "FINAL NOTICE: Your vehicle warranty is expiring. Extend now: car-scam.co"
    ]
    
    # Start the attack simulation
    print(f"\n{Fore.YELLOW}[*] Starting SMS bombing simulation to {phone}")
    print(f"{Fore.YELLOW}[*] Preparing to send {count} messages...\n")
    time.sleep(1)
    
    # Track services used
    services = [
        "SMSBomber Pro", "TextBlaster", "MessageFlood", "SMSRush", 
        "BulkMessenger", "SpeedSMS", "QuickText", "RapidMessage",
        "SMSGateway", "MessageHub", "TextStorm", "FlashSMS",
        "BurstText", "WaveMessage", "PulseSMS", "ThunderText"
    ]
    
    # Log the attack attempt
    log_threat("SMS DOS Attack", f"SMS bombing simulation to {phone} with {count} messages", "Medium")
    
    # Progress variables
    success_count = 0
    fail_count = 0
    
    # Simulated attack loop
    for i in range(1, count + 1):
        # Select a random service and message
        service = random.choice(services)
        message = random.choice(spam_messages)
        message_preview = message[:20] + "..." if len(message) > 20 else message
        
        # Simulate success or failure (90% success rate)
        success = random.random() < 0.9
        
        # Create request details
        request_id = uuid.uuid4().hex[:8]
        delay = random.uniform(0.5, 2.0)
        time.sleep(delay)
        
        # Print progress with different colors based on success
        timestamp = datetime.now().strftime("%H:%M:%S")
        if success:
            success_count += 1
            print(f"{Fore.GREEN}[+] {timestamp} - Message {i}/{count} sent via {service}")
            print(f"{Fore.GREEN}    └─ ID: {request_id} | Content: \"{message_preview}\"")
        else:
            fail_count += 1
            print(f"{Fore.RED}[!] {timestamp} - Message {i}/{count} failed via {service}")
            print(f"{Fore.RED}    └─ Error: Rate limit exceeded or service unavailable")
        
        # Update progress
        progress = int((i / count) * 20)
        bar = "█" * progress + "░" * (20 - progress)
        percent = (i / count) * 100
        print(f"{Fore.CYAN}[*] Progress: [{bar}] {percent:.1f}%")
    
    # Summary
    print(f"\n{Fore.YELLOW}[*] Attack simulation completed!")
    print(f"{Fore.GREEN}[+] Successfully sent: {success_count} messages")
    print(f"{Fore.RED}[!] Failed: {fail_count} messages")
    print(f"{Fore.YELLOW}[*] Target number: {phone}")
    
    input(f"\n{Fore.YELLOW}Press Enter to continue...")
    
def log_visualizer():
    """Visualize logs in a fancy terminal-based UI with real-time updates"""
    global log_visualizer_running, stop_threads
    
    log_visualizer_running = True
    stop_threads = False
    
    # Load existing logs from the data file
    data = load_data()
    logs = data["threat_logs"]
    
    # Ensure we have some logs to display
    if not logs:
        print(f"{Fore.YELLOW}[*] No logs found in the database")
        print(f"{Fore.YELLOW}[*] Generating sample logs for visualization...")
        
        # Generate some sample logs
        sample_event_types = [
            "Brute Force", "SQL Injection", "XSS Attack", "File Integrity Violation",
            "Suspicious Login", "Malware Detected", "Ransomware Activity", "Data Exfiltration",
            "Network Scan", "DDoS Attack", "Privilege Escalation", "Command Injection"
        ]
        
        for _ in range(20):
            event_type = random.choice(sample_event_types)
            severity = random.choice(["Low", "Medium", "High", "Critical"])
            
            # Generate random timestamps within the last day
            random_minutes = random.randint(1, 24*60)
            timestamp = (datetime.now() - timedelta(minutes=random_minutes)).strftime("%Y-%m-%d %H:%M:%S")
            
            # Create sample log details
            if event_type == "Brute Force":
                details = f"Login attempts from IP {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            elif event_type == "SQL Injection":
                details = f"Malicious query detected in web form: ' OR '1'='1"
            elif event_type == "XSS Attack":
                details = f"Cross-site scripting attempt in parameter 'search': <script>alert('XSS')</script>"
            elif event_type == "File Integrity Violation":
                details = f"File /etc/passwd hash changed"
            elif event_type == "Suspicious Login":
                details = f"User 'admin' logged in from unusual location: {random.choice(['Russia', 'China', 'Brazil', 'Nigeria'])}"
            else:
                details = f"Detected in {random.choice(['network traffic', 'log files', 'system memory', 'registry', 'file system'])}"
            
            # Add the sample log
            logs.append({
                "timestamp": timestamp,
                "type": event_type, 
                "details": details,
                "severity": severity
            })
        
        # Sort logs by timestamp
        logs.sort(key=lambda x: x["timestamp"])
        
        # Save the sample logs
        data["threat_logs"] = logs
        save_data(data)
        print(f"{Fore.GREEN}[+] Generated {len(logs)} sample logs")
    
    print(f"{Fore.YELLOW}[*] Starting Log Visualizer...")
    print(f"{Fore.YELLOW}[*] Press 'q' to exit, arrow keys to navigate\n")
    time.sleep(1)
    
    # Visualization settings
    page_size = 10
    current_page = 0
    filter_severity = None  # None means show all
    filter_type = None      # None means show all
    sort_order = "desc"     # desc = newest first, asc = oldest first
    highlight_mode = False  # For highlighting search results
    search_term = ""        # For searching logs
    layout_mode = "normal"  # normal, compact, detailed
    
    # Get the event types and severities for filters
    event_types = sorted(list(set([log["type"] for log in logs])))
    severities = ["Critical", "High", "Medium", "Low"]
    
    max_pages = max(1, (len(logs) - 1) // page_size + 1)
    
    # Function to apply filters and return filtered logs
    def get_filtered_logs():
        filtered = logs
        
        # Apply severity filter
        if filter_severity:
            filtered = [log for log in filtered if log["severity"] == filter_severity]
        
        # Apply type filter
        if filter_type:
            filtered = [log for log in filtered if log["type"] == filter_type]
        
        # Apply search term if any
        if search_term:
            filtered = [log for log in filtered 
                      if search_term.lower() in log["type"].lower() or 
                         search_term.lower() in log["details"].lower()]
        
        # Apply sorting
        filtered.sort(key=lambda x: x["timestamp"], 
                     reverse=(sort_order == "desc"))
        
        return filtered
    
    # Function to draw the log interface
    def draw_interface():
        nonlocal max_pages
        
        # Get filtered logs
        filtered_logs = get_filtered_logs()
        max_pages = max(1, (len(filtered_logs) - 1) // page_size + 1)
        
        # Calculate which logs to display on the current page
        start_idx = current_page * page_size
        page_logs = filtered_logs[start_idx:start_idx + page_size]
        
        clear_screen()
        
        # Draw header
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}ZT-CYBERSEC LOG VISUALIZER{' ' * 48}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Draw filters section
        severity_display = filter_severity if filter_severity else "All"
        type_display = filter_type if filter_type else "All"
        search_display = f"'{search_term}'" if search_term else "None"
        
        print(f"{Fore.CYAN}║ {Fore.WHITE}Filters: {Fore.GREEN}Severity: {severity_display} | Type: {type_display} | Search: {search_display}{' ' * (17-len(search_display))}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Sort: {Fore.GREEN}{sort_order.upper()} | Layout: {layout_mode.capitalize()} | Page: {current_page+1}/{max_pages}{' ' * 32}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Draw column headers based on layout mode
        if layout_mode == "compact":
            print(f"{Fore.CYAN}║ {Fore.YELLOW}Time{' ' * 7} | {Fore.YELLOW}Type{' ' * 15} | {Fore.YELLOW}Severity{' ' * 2} | {Fore.YELLOW}Details{' ' * 24}{Fore.CYAN}║")
        else: # normal or detailed
            print(f"{Fore.CYAN}║ {Fore.YELLOW}Timestamp{' ' * 10} | {Fore.YELLOW}Type{' ' * 15} | {Fore.YELLOW}Severity{' ' * 2} | {Fore.YELLOW}Details{' ' * 19}{Fore.CYAN}║")
        
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        
        # Draw logs based on layout mode
        if not page_logs:
            print(f"{Fore.CYAN}║ {Fore.RED}No logs match the current filters{' ' * 47}{Fore.CYAN}║")
        else:
            for log in page_logs:
                # Format based on severity
                if log["severity"] == "Critical":
                    severity_color = Fore.MAGENTA
                elif log["severity"] == "High":
                    severity_color = Fore.RED
                elif log["severity"] == "Medium": 
                    severity_color = Fore.YELLOW
                else:
                    severity_color = Fore.GREEN
                
                # Highlight search terms if in highlight mode
                details = log["details"]
                log_type = log["type"]
                
                if highlight_mode and search_term:
                    # Highlight search term in details and type
                    if search_term.lower() in details.lower():
                        start = details.lower().find(search_term.lower())
                        end = start + len(search_term)
                        details = (details[:start] + Fore.BLACK + Back.WHITE + 
                                  details[start:end] + Style.RESET_ALL + severity_color + 
                                  details[end:])
                    
                    if search_term.lower() in log_type.lower():
                        start = log_type.lower().find(search_term.lower())
                        end = start + len(search_term)
                        log_type = (log_type[:start] + Fore.BLACK + Back.WHITE + 
                                   log_type[start:end] + Style.RESET_ALL + severity_color +
                                   log_type[end:])
                
                # Format timestamp based on layout mode
                if layout_mode == "compact":
                    # Show only time for compact mode
                    try:
                        dt = datetime.strptime(log["timestamp"], "%Y-%m-%d %H:%M:%S")
                        timestamp = dt.strftime("%H:%M:%S")
                    except:
                        timestamp = log["timestamp"][-8:]
                else:
                    timestamp = log["timestamp"]
                
                # Truncate fields based on layout mode
                if layout_mode == "compact":
                    type_field = log_type[:15].ljust(15)
                    details_field = details[:30].ljust(30)
                elif layout_mode == "normal":
                    type_field = log_type[:15].ljust(15)
                    details_field = details[:25].ljust(25)
                else:  # detailed
                    type_field = log_type[:15].ljust(15)
                    details_field = details[:25].ljust(25)
                
                # Print the log entry
                print(f"{Fore.CYAN}║ {Fore.WHITE}{timestamp.ljust(19)} {Fore.CYAN}│ {severity_color}{type_field} {Fore.CYAN}│ {severity_color}{log['severity'].ljust(9)} {Fore.CYAN}│ {severity_color}{details_field}{Fore.CYAN} ║")
                
                # For detailed view, add a second line with more details if needed
                if layout_mode == "detailed" and len(log["details"]) > 25:
                    extra_details = log["details"][25:75].ljust(51)
                    print(f"{Fore.CYAN}║ {' ' * 19} {Fore.CYAN}│ {' ' * 15} {Fore.CYAN}│ {' ' * 9} {Fore.CYAN}│ {severity_color}{extra_details}{Fore.CYAN} ║")
        
        # Fill remaining rows if needed
        rows_to_fill = page_size - len(page_logs)
        if layout_mode == "detailed":
            # Detailed mode takes up to 2 rows per log
            # This is a simplification - ideally we'd count exactly how many detail lines we printed
            rows_to_fill = max(0, page_size - (len(page_logs) * 1.5))
        
        for _ in range(int(rows_to_fill)):
            print(f"{Fore.CYAN}║ {' ' * 76} ║")
        
        # Draw footer with commands
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Commands: q-Quit | f-Filter | s-Search | t-Sort | l-Layout | h-Highlight{' ' * 9}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.WHITE}Navigation: ◄,► Page | ▲,▼ Scroll{' ' * 42}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
    
    # Function to add a random log entry (for real-time simulation)
    def add_random_log():
        event_types = [
            "Brute Force", "SQL Injection", "XSS Attack", "File Integrity Violation",
            "Suspicious Login", "Malware Detected", "Ransomware Activity", "Data Exfiltration",
            "Network Scan", "DDoS Attack", "Privilege Escalation", "Command Injection"
        ]
        
        event_type = random.choice(event_types)
        severity = random.choice(["Low", "Medium", "High", "Critical"])
        
        # Create sample log details
        if event_type == "Brute Force":
            details = f"Login attempts from IP {random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        elif event_type == "SQL Injection":
            details = f"Malicious query detected in web form: ' OR '1'='1"
        elif event_type == "XSS Attack":
            details = f"Cross-site scripting attempt in parameter 'search': <script>alert('XSS')</script>"
        elif event_type == "File Integrity Violation":
            details = f"File /etc/passwd hash changed"
        elif event_type == "Suspicious Login":
            details = f"User 'admin' logged in from unusual location: {random.choice(['Russia', 'China', 'Brazil', 'Nigeria'])}"
        else:
            details = f"Detected in {random.choice(['network traffic', 'log files', 'system memory', 'registry', 'file system'])}"
        
        # Add the log
        new_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": event_type,
            "details": details,
            "severity": severity
        }
        
        logs.append(new_log)
        data["threat_logs"] = logs
        save_data(data)
    
    # Set up a thread to add random logs periodically
    def random_log_generator():
        while not stop_threads:
            time.sleep(random.uniform(3, 8))  # Add log every 3-8 seconds
            if random.random() < 0.7:  # 70% chance to add a log
                add_random_log()
    
    # Start the log generator thread
    log_gen_thread = threading.Thread(target=random_log_generator)
    log_gen_thread.daemon = True
    log_gen_thread.start()
    
    # Main visualization loop
    try:
        while not stop_threads:
            draw_interface()
            
            # Wait for keypress with a timeout to allow periodic refresh
            start_time = time.time()
            key_pressed = False
            
            # Check for key press with timeout
            while time.time() - start_time < 1 and not key_pressed:
                if msvcrt_available():
                    import msvcrt
                    if msvcrt.kbhit():
                        key = msvcrt.getch()
                        key_pressed = True
                        
                        # Handle navigation
                        if key == b'q':  # Quit
                            stop_threads = True
                            break
                        elif key == b'H':  # Up arrow
                            # Scroll behavior depends on layout
                            pass
                        elif key == b'P':  # Down arrow
                            # Scroll behavior depends on layout
                            pass
                        elif key == b'M':  # Right arrow - next page
                            if current_page < max_pages - 1:
                                current_page += 1
                        elif key == b'K':  # Left arrow - previous page
                            if current_page > 0:
                                current_page -= 1
                        elif key == b'f':  # Filter
                            # Toggle between severity filters
                            if filter_severity is None:
                                filter_severity = "Critical"
                            elif filter_severity == "Critical":
                                filter_severity = "High"
                            elif filter_severity == "High":
                                filter_severity = "Medium"
                            elif filter_severity == "Medium":
                                filter_severity = "Low"
                            else:
                                filter_severity = None
                            current_page = 0  # Reset to first page
                        elif key == b't':  # Toggle event type filter
                            if not event_types:
                                pass  # No types available
                            elif filter_type is None and event_types:
                                filter_type = event_types[0]
                            else:
                                # Find current index and go to next
                                try:
                                    idx = event_types.index(filter_type)
                                    idx = (idx + 1) % len(event_types)
                                    filter_type = event_types[idx]
                                except:
                                    filter_type = None
                            current_page = 0  # Reset to first page
                        elif key == b's':  # Search
                            # Simple search input
                            print(f"{Fore.GREEN}Enter search term (empty to clear): ", end="")
                            search_term = input().strip()
                            current_page = 0  # Reset to first page
                        elif key == b'h':  # Toggle highlight mode
                            highlight_mode = not highlight_mode
                        elif key == b'l':  # Toggle layout mode
                            if layout_mode == "normal":
                                layout_mode = "compact"
                            elif layout_mode == "compact":
                                layout_mode = "detailed"
                            else:
                                layout_mode = "normal"
                time.sleep(0.05)
                
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"{Fore.RED}[!] Error in log visualizer: {e}")
    finally:
        log_visualizer_running = False
        stop_threads = True
        print(f"\n{Fore.YELLOW}[*] Log Visualizer stopped")
        input(f"{Fore.YELLOW}[*] Press Enter to continue...")

def main():
    """Display the main menu of the cybersecurity toolkit"""
    global current_user, stop_threads
    
    while True:
        print_banner()
        
        # Only show relevant tools based on role
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗")
        print(f"{Fore.CYAN}║ {Fore.YELLOW}ZERO TRUST CYBERSECURITY TOOLKIT MENU{' ' * 42}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════════════════════════════════════╣")
        print(f"{Fore.CYAN}║ {Fore.GREEN}1. MFA Brute Force Simulator      {Fore.CYAN}║ {Fore.GREEN}2. Port Scanner{' ' * 27}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}3. Real-time Packet Sniffer       {Fore.CYAN}║ {Fore.GREEN}4. MAC Address Spoof Detector{' ' * 15}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}5. SOC Security Dashboard         {Fore.CYAN}║ {Fore.GREEN}6. Firewall Configuration{' ' * 18}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}7. File Integrity Monitor         {Fore.CYAN}║ {Fore.GREEN}8. Honeypot Deployer{' ' * 23}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}9. Threat Intelligence Feeds      {Fore.CYAN}║ {Fore.GREEN}10. Log Analysis & Visualization{' ' * 12}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}11. Device Trust Assessment      {Fore.CYAN}║ {Fore.GREEN}12. Insider Threat Tracker{' ' * 18}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.GREEN}13. Hash Reverser                {Fore.CYAN}║ {Fore.GREEN}14. Settings & Configuration{' ' * 15}{Fore.CYAN}║")
        print(f"{Fore.CYAN}║ {Fore.RED}0. Exit{' ' * 71}{Fore.CYAN}║")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝")
        
        choice = input(f"\n{Fore.GREEN}[+] Enter your choice (0-14): ")
        
        if choice == '0':
            print(f"\n{Fore.YELLOW}[*] Shutting down Zero Trust Cybersecurity Toolkit...")
            stop_threads = True
            time.sleep(1)
            clear_screen()
            sys.exit(0)
        elif choice == '1':
            mfa_bruteforce()
        elif choice == '2':
            target = input(f"{Fore.GREEN}[+] Enter target IP address: ")
            scan_ports(target)
        elif choice == '3':
            packet_sniffer()
        elif choice == '4':
            mac_spoof_detector()
        elif choice == '5':
            try:
                print(f"{Fore.YELLOW}[*] Press Ctrl+C to exit the dashboard")
                soc_dashboard()
            except KeyboardInterrupt:
                pass
        elif choice == '6':
            firewall_simulator()
        elif choice == '7':
            sms_dos_attack()
        elif choice == '8':
            login_honeypot()
        elif choice == '9':
            sms_dos_attack()
        elif choice == '10':
            log_visualizer()
        elif choice == '11':
            sms_dos_attack()
        elif choice == '12':
            insider_threat_tracker()
        elif choice == '13':
            file_hash_checker()
        # Add other menu options here...
        else:
            print(f"\n{Fore.RED}[!] Invalid choice or feature not yet implemented")
            input(f"{Fore.YELLOW}[*] Press Enter to continue...")

if __name__ == '__main__':
    main()
