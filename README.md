# Simple Network Intrusion Detection System (IDS)

## Description
This is a lightweight Python-based Intrusion Detection System (IDS) that monitors network traffic in real time and detects potential port scan activities.
It captures packets using the Scapy library, identifies the source IP addresses, classifies ports as safe or suspicious, and logs activities for analysis.

## Features
1. Real-time network packet sniffing
2. Detection of potential port scans based on suspicious port access thresholds
3. Differentiates between known safe ports (e.g., HTTP/HTTPS) and others
4. Logs: Suspicious activities with timestamps (ids_alerts.log) and all unique IPs ever seen (ids_all_ips.log)
5. Configurable detection thresholds and time windows

## Requirments
Python 3.7+
Scapy (pip install scapy)
(Windows) Install Npcap for packet capturing (https://nmap.org/npcap/)

## How to Run
python ids_detector.py
