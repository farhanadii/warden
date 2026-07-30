from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[TCP].name if TCP in packet else "UDP" if UDP in packet else "Other"
        print(f"{src_ip} -> {dst_ip} ({proto})")

def start_netcut(count=100):
    sniff(prn=packet_callback, count=count)

if __name__ == "__main__":
    start_netcut()