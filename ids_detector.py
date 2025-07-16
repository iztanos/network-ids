from scapy.all import sniff, IP, TCP, UDP
import time
import logging
from collections import defaultdict

# Track packet counts per IP
packet_counts = defaultdict(int)

# Track IPs accessing safe and suspicious ports separately
ip_safe_ports = defaultdict(set)
ip_suspicious_ports = defaultdict(set)

# Timing and detection thresholds
start_time = time.time()
TIME_WINDOW = 10               # Time window in seconds for scanning activity
PORT_SCAN_THRESHOLD = 20       # Threshold for number of suspicious ports accessed to trigger alert

# Define known safe ports to exclude from alerts
SAFE_PORTS = {80, 443}

# Set to keep track of IPs already logged as known (to avoid repeat alerts)
known_ips = set()

# Setup logger for suspicious activity alerts
alert_logger = logging.getLogger("AlertLogger")
alert_logger.setLevel(logging.INFO)
alert_handler = logging.FileHandler("ids_alerts.log", mode="a")
alert_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
alert_logger.addHandler(alert_handler)

# Setup logger for tracking all unique IPs seen
ip_logger = logging.getLogger("IPLogger")
ip_logger.setLevel(logging.INFO)
ip_handler = logging.FileHandler("ids_all_ips.log", mode="a")
ip_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", "%Y-%m-%d %H:%M:%S"))
ip_logger.addHandler(ip_handler)

logging.info("IDS started. Monitoring network traffic for suspicious activity.")

def process_packet(packet):
    """
    Callback function to process each sniffed packet.
    Tracks safe and suspicious ports accessed by source IPs.
    Every TIME_WINDOW seconds, analyzes and logs port scan alerts.
    """
    global start_time

    # Process only IP packets
    if IP in packet:
        src_ip = packet[IP].src
        packet_counts[src_ip] += 1

        # Check TCP packets
        if TCP in packet:
            dport = packet[TCP].dport
            if dport in SAFE_PORTS:
                ip_safe_ports[src_ip].add(dport)
            else:
                ip_suspicious_ports[src_ip].add(dport)

        # Check UDP packets
        elif UDP in packet:
            dport = packet[UDP].dport
            if dport in SAFE_PORTS:
                ip_safe_ports[src_ip].add(dport)
            else:
                ip_suspicious_ports[src_ip].add(dport)

        # Periodically analyze and reset data
        if time.time() - start_time > TIME_WINDOW:
            print("\n--- Scanning ---")
            # Combine all IPs that accessed any ports in the time window
            ips_to_check = set(ip_safe_ports) | set(ip_suspicious_ports)

            for ip in ips_to_check:
                safe_ports = ip_safe_ports.get(ip, set())
                suspicious_ports = ip_suspicious_ports.get(ip, set())

                # Print info logs for both safe and suspicious ports
                print(f"[INFO] {ip} accessed safe ports: {sorted(list(safe_ports))}")
                print(f"[INFO] {ip} accessed suspicious ports: {sorted(list(suspicious_ports))}")

                # Log and alert for new IPs seen for the first time
                if ip not in known_ips:
                    known_ips.add(ip)
                    ip_logger.info(f"New IP detected: {ip}")
                    print(f"[NEW] Detected new IP: {ip}")

                # Trigger alert if suspicious ports accessed exceed threshold
                if len(suspicious_ports) > PORT_SCAN_THRESHOLD:
                    alert_msg = (f"ALERT: Possible port scan from {ip} - "
                                 f"tried {len(suspicious_ports)} suspicious ports: {sorted(list(suspicious_ports))}")
                    print(alert_msg)
                    alert_logger.info(alert_msg)

            # Clear data for next interval
            ip_safe_ports.clear()
            ip_suspicious_ports.clear()
            start_time = time.time()

print("Starting Port Scan Detection...")

try:
    # Start sniffing packets indefinitely (requires appropriate permissions)
    sniff(prn=process_packet, store=0)
except KeyboardInterrupt:
    logging.info("IDS stopped by user.")
    print("\n[INFO] IDS stopped by user.")






  