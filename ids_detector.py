from scapy.all import sniff, IP, TCP, UDP
import time
import logging
from collections import defaultdict

packet_counts = defaultdict(int)
ip_counts = defaultdict(int) 
ip_safe_ports = defaultdict(set)    
ip_suspicious_ports = defaultdict(set)  
start_time = time.time()
TIME_WINDOW = 10
PORT_SCAN_THRESHOLD = 2
ip_ports = defaultdict(set)
SAFE_PORTS = {80, 443}
UNSAFE_PORTS = {}
seen_ips = set()
known_ips = set()


# Alert logger (for suspicious activity)
alert_logger = logging.getLogger("AlertLogger")
alert_logger.setLevel(logging.INFO)
alert_handler = logging.FileHandler("ids_alerts.log", mode="a")
alert_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
alert_logger.addHandler(alert_handler)

# Unique IP logger
ip_logger = logging.getLogger("IPLogger")
ip_logger.setLevel(logging.INFO)
ip_handler = logging.FileHandler("ids_all_ips.log", mode="a")
ip_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
ip_logger.addHandler(ip_handler)

logging.info("IDS started. Monitoring network traffic for suspicious activity.")

def process_packet(packet):
    global start_time

   
    if IP in packet:
        #print("Packet from:", packet[IP].src)
        src_ip = packet[IP].src 
        packet_counts[src_ip] += 1

        if TCP in packet:
            dport = packet[TCP].dport
            if dport in SAFE_PORTS:
                #print(f"TCP Packet from {src_ip} to port {dport}")
                ip_safe_ports[src_ip].add(dport)
            else:
                ip_suspicious_ports[src_ip].add(dport)

        elif UDP in packet:
            dport = packet[UDP].dport
            if dport in SAFE_PORTS:
                #print(f"UDP Packet from {src_ip} to port {dport}")
                ip_safe_ports[src_ip].add(dport)
            else:
                ip_suspicious_ports[src_ip].add(dport)

        if time.time() - start_time > TIME_WINDOW:
            print("\n--- Scanning ---")
            for ip in set(ip_safe_ports) | set(ip_suspicious_ports):
                safe_ports = ip_safe_ports.get(ip, set())
                suspicious_ports = ip_suspicious_ports.get(ip, set())

                # Print safe and suspicious port info every time
                print(f"[INFO] {ip} accessed safe ports: {sorted(list(safe_ports))}")
                print(f"[INFO] {ip} accessed suspicious ports: {sorted(list(suspicious_ports))}")

                # Check if IP is new — log and print new IP alert once
                if ip not in known_ips:
                    known_ips.add(ip)
                    ip_logger.info(f"New IP detected: {ip}")
                    print(f"[NEW] Detected new IP: {ip}")

                # Alert on suspicious ports over threshold
                if len(suspicious_ports) > PORT_SCAN_THRESHOLD:
                    alert_msg = (f"ALERT: Possible port scan from {ip} - "
                                 f"tried {len(suspicious_ports)} suspicious ports: {sorted(list(suspicious_ports))}")
                    print(alert_msg)
                    alert_logger.info(alert_msg)
            # Reset counters and timer
            ip_safe_ports.clear()
            ip_suspicious_ports.clear()
            start_time = time.time()
                

print("Starting Port Scan Detection...")

try:
    # if using Ethernet
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    logging.info("IDS stopped by user.")
    print("\n[INFO] IDS stopped by user.")

# if using WiFi
#sniff(prn=process_packet, store=0, iface = "\\Device\\NPF_{0E972713-ECB7-48F2-8393-CE914AC63AAB}")



  