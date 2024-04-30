from scapy.all import *

# Define a function to analyze packets
def analyze_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        print(f"IP Packet: {ip_src} -> {ip_dst}, Protocol: {protocol}")

    if TCP in packet:
        tcp_src = packet[TCP].sport
        tcp_dst = packet[TCP].dport
        print(f"TCP Packet: {tcp_src} -> {tcp_dst}")

    if UDP in packet:
        udp_src = packet[UDP].sport
        udp_dst = packet[UDP].dport
        print(f"UDP Packet: {udp_src} -> {udp_dst}")

# Sniff network traffic
def sniff_network(interface):
    print(f"Sniffing on interface {interface}...")
    sniff(iface=interface, prn=analyze_packet)

if __name__ == "__main__":
    # Specify the network interface to sniff on (e.g., "Ethernet" for Ethernet)
    interface = "Wi-Fi"
    sniff_network(interface)
