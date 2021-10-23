import sys
import scapy.all as scapy


UNDER_ATTACK = False

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, lfilter=process_sniffed_packet, stop_filter=process_sniffed_packet)

def process_sniffed_packet(packet):
    global UNDER_ATTACK
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 and not UNDER_ATTACK:
        try:
            real_mac = get_mac(packet[scapy.ARP].psrc)
            response_mac = packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                UNDER_ATTACK = True
        except IndexError:
            pass
    elif packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2 and UNDER_ATTACK:
        return True

def main(filepath):
    sniff(scapy.conf.iface)
    with open(filepath, "w") as write:
        write.write("Someone in your network in ARP Spoof attack! (it can be you).")