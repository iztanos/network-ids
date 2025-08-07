from modules.database import init_db, log_alert_to_db
import argparse
from scapy.all import sniff, ICMP
from modules.packet_processor import process_packet
from modules.logging_config import setup_logging
import logging

import argparse

def parse_arguments():
    parser = argparse.ArgumentParser(description="Port Scan Detection")
    parser.add_argument("--interface", required=True, help="Network interface to use")
    parser.add_argument("--tcp-threshold", type=int, required=True, help="TCP threshold for alerting")
    parser.add_argument("--udp-threshold", type=int, required=True, help="UDP threshold for alerting")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")
    return parser.parse_args()

def main(interface, tcp_threshold, udp_threshold, test_mode):
    args = parse_arguments()
    interface = args.interface
    tcp_threshold = args.tcp_threshold
    udp_threshold = args.udp_threshold
    test_mode = args.test_mode

    setup_logging()
    print("Starting Port Scan Detection...")

    if test_mode:
        print("Running in test mode. No actual packet sniffing will be performed.")
        # In test mode, you can add mock data or simulate the process_packet function
        # For example: process_packet(mock_packet, tcp_threshold, udp_threshold)
        return

    try:
        sniff(iface=interface, prn=lambda packet: process_packet(packet, tcp_threshold, udp_threshold), store=0)
    except KeyboardInterrupt:
        logging.info("IDS stopped by user.")
        print("\n[INFO] IDS stopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Intrusion Detection System")
    parser.add_argument("--interface", type=str, default="eth0", help="Network interface to use")
    parser.add_argument("--tcp-threshold", type=int, default=2, help="TCP port scan threshold")
    parser.add_argument("--udp-threshold", type=int, default=5, help="UDP port scan threshold")
    parser.add_argument("--test-mode", action="store_true", help="Run in test mode")

    args = parser.parse_args()

    main(args.interface, args.tcp_threshold, args.udp_threshold, args.test_mode)
