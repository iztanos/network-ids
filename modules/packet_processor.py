from scapy.all import IP, TCP, UDP, ICMP
import time
from collections import defaultdict
from modules.database import log_alert_to_db
from modules.logging_config import log_packet_data
from modules.alerts import send_email_alert, send_slack_alert

packet_counts = defaultdict(int)
ip_counts = defaultdict(int)
ip_safe_ports = defaultdict(set)
ip_tcp_suspicious_ports = defaultdict(set)
ip_udp_suspicious_ports = defaultdict(set)
start_time = time.time()
TIME_WINDOW = 10
SAFE_PORTS = {80, 443}
UNSAFE_PORTS = {}
seen_ips = set()
known_ips = set()

import socket

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def process_packet(packet, tcp_threshold, udp_threshold):
    global start_time

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if packet.haslayer(ICMP) else "Unknown"
        packet_size = len(packet)
        ttl = packet[IP].ttl
        src_hostname = get_hostname(src_ip)
        dst_hostname = get_hostname(dst_ip)

        tcp_flags = None
        if TCP in packet:
            tcp_flags = {
                "FIN": packet[TCP].flags.F,
                "SYN": packet[TCP].flags.S,
                "RST": packet[TCP].flags.R,
                "PSH": packet[TCP].flags.P,
                "ACK": packet[TCP].flags.A,
                "URG": packet[TCP].flags.U,
                "ECE": packet[TCP].flags.E,
                "CWR": packet[TCP].flags.C
            }

        dport = None
        if TCP in packet:
            dport = packet[TCP].dport
            if dport in SAFE_PORTS:
                ip_safe_ports[src_ip].add(dport)
            else:
                ip_tcp_suspicious_ports[src_ip].add(dport)

        elif UDP in packet:
            dport = packet[UDP].dport
            if dport in SAFE_PORTS:
                ip_safe_ports[src_ip].add(dport)
            else:
                ip_udp_suspicious_ports[src_ip].add(dport)

        log_data = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "packet_size": packet_size,
            "ttl": ttl,
            "src_hostname": src_hostname,
            "dst_hostname": dst_hostname,
            "tcp_flags": tcp_flags,
            "dport": dport
        }

        # Log the data using the new logging function
        log_packet_data(log_data)

        if time.time() - start_time > TIME_WINDOW:
            print("\n--- Scanning ---")
            for ip in set(ip_safe_ports) | set(ip_tcp_suspicious_ports) | set(ip_udp_suspicious_ports):
                safe_ports = ip_safe_ports.get(ip, set())
                tcp_suspicious_ports = ip_tcp_suspicious_ports.get(ip, set())
                udp_suspicious_ports = ip_udp_suspicious_ports.get(ip, set())

                print(f"[INFO] {ip} accessed safe ports: {sorted(list(safe_ports))}")
                print(f"[INFO] {ip} accessed suspicious TCP ports: {sorted(list(tcp_suspicious_ports))}")
                print(f"[INFO] {ip} accessed suspicious UDP ports: {sorted(list(udp_suspicious_ports))}")

                if ip not in known_ips:
                    known_ips.add(ip)
                    print(f"[NEW] Detected new IP: {ip}")

                if len(tcp_suspicious_ports) > tcp_threshold:
                    alert_msg = (f"ALERT: Possible TCP port scan from {ip} - "
                                 f"tried {len(tcp_suspicious_ports)} suspicious ports: {sorted(list(tcp_suspicious_ports))}")
                    print(alert_msg)
                    log_alert_to_db(ip, "TCP", "Port Scan", alert_msg, tcp_suspicious_ports)
                    send_email_alert("TCP Port Scan Alert", alert_msg, "admin@example.com")
                    # Replace 'https://hooks.slack.com/services/your/webhook/url' with your actual Slack webhook URL
                    send_slack_alert("https://hooks.slack.com/services/your/webhook/url", alert_msg)

                if len(udp_suspicious_ports) > udp_threshold:
                    alert_msg = (f"ALERT: Possible UDP port scan from {ip} - "
                                 f"tried {len(udp_suspicious_ports)} suspicious ports: {sorted(list(udp_suspicious_ports))}")
                    print(alert_msg)
                    log_alert_to_db(ip, "UDP", "Port Scan", alert_msg, udp_suspicious_ports)
                    send_email_alert("UDP Port Scan Alert", alert_msg, "admin@example.com")
                    # Replace 'https://hooks.slack.com/services/your/webhook/url' with your actual Slack webhook URL
                    send_slack_alert("https://hooks.slack.com/services/your/webhook/url", alert_msg)

            ip_safe_ports.clear()
            ip_tcp_suspicious_ports.clear()
            ip_udp_suspicious_ports.clear()
            start_time = time.time()
