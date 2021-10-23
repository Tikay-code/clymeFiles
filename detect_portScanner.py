import sys
from time import time

import scapy.all
from scapy.all import sniff

ip_to_ports = dict()

# Nr of ports in timespan seconds
nr_of_diff_ports = 10
portscan_timespan = 10

data = ""

def detect_portscan(packet):
    global data
    ip = packet.getlayer("IP")
    tcp = packet.getlayer("TCP")

    # Remember scanned port and time in unix format
    ip_to_ports.setdefault(ip.src, {})\
               [str(tcp.dport)] = int(time())

    # Source IP has scanned too much different ports?
    if len(ip_to_ports[ip.src]) >= nr_of_diff_ports:
        scanned_ports = ip_to_ports[ip.src].items()

        # Check recorded time of each scan
        for (scanned_port, scan_time) in scanned_ports:

            # Scanned port not in timeout span? Delete it
            if scan_time + portscan_timespan < int(time()):
                del ip_to_ports[ip.src][scanned_port]

        # Still too much scanned ports?
        if len(ip_to_ports[ip.src]) >= nr_of_diff_ports:
            data = ("Portscan detected from " + ip.src + " | Target: " + ip.dst)

            del ip_to_ports[ip.src]


def stopSniffing(packet):
    if len(data) != 0:
        return True
    else:
        return False

def main(filepath):
    global data
    sniff(prn=detect_portscan,
          filter="tcp",
          iface=scapy.all.conf.iface,
          store=0,
          stop_filter=stopSniffing)
    print("Done!")
    with open(filepath, "a") as file:
        print("Write .. ")
        file.write(data)
        data = ""
        # print("Scanned ports " + ",".join(ip_to_ports[ip.src].keys()) + "\n")
        # print("Target: {}".format(ip.dst))
