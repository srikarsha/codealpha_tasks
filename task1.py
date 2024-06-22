from scapy.all import sniff, IP, TCP, UDP, wrpcap, conf
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            print(f"TCP Packet: {ip_src}:{packet[TCP].sport} -> {ip_dst}:{packet[TCP].dport}")
        elif UDP in packet:
            print(f"UDP Packet: {ip_src}:{packet[UDP].sport} -> {ip_dst}:{packet[UDP].dport}")
        else:
            print(f"IP Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")
if conf.use_pcap:
    print("Using Npcap/WinPcap for packet capture")
else:
    print("Npcap/WinPcap is not available, please install it from https://nmap.org/npcap/")

try:
    print("Starting packet capture...")
    packets = sniff(filter="ip", prn=packet_callback, count=10)
    file_name = 'captured_packets.pcap'
    wrpcap(file_name, packets)
    print(f"Captured packets saved to {file_name}")
except RuntimeError as e:
    print(f"Error: {e}")
    print("Make sure Npcap is installed and the script is run with sufficient privileges.")
