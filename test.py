from scapy.all import sniff, IP

def show_ip(packet):
    if IP in packet:
        print(packet[IP].src)

sniff(prn=show_ip)
