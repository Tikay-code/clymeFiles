import sys
sys.path.append("C:\\Users\\User\Documents\To The Distance\Python\Lib\site-packages\scapy")

from scapy.all import *
import argparse
import netifaces
import time
import socket
import os
from mac_vendor_lookup import MacLookup



def get_gateway_ip():
    gateways = netifaces.gateways()
    default_gateway = gateways['default'][netifaces.AF_INET][0]
    return default_gateway

def scan(ip):
    arp_req_frame = ARP(pdst=ip)

    broadcast_ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame

    answered_list = srp(broadcast_ether_arp_req_frame, timeout=2, verbose=False)[0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip": answered_list[i][1].psrc, "mac": answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result

def main(filepath, arpit):
    network_to_scan = get_gateway_ip() + "/24"
    printed_results = []
    results = []
    while True:
        for result in scan(network_to_scan):
            if result not in printed_results:
                printed_results.append(result)
                hostName = socket.gethostbyaddr(result.get("ip"))[0]
                data = "IP: " + result.get("ip") + " | MAC: " + result.get("mac") + " | " + hostName

                results.append(data)

                with open(filepath, "w") as hostfile:
                    hostfile.write(data)

                if os.path.isfile(arpit):
                    with open(arpit, "r+") as spoofit:
                        if result.get('ip') not in spoofit.read():
                            spoofit.write(result.get('ip') + "\n")
                if not os.path.exists(arpit):
                    print("Creating it.. ")
                    open(arpit, "w")
                    with open(arpit, "r+") as spoofit:
                        if result.get('ip') not in spoofit.read():
                            spoofit.write(result.get('ip') + "\n")

def resolve_host_name(ip):
    results = []
    try:
        results = socket.gethostbyaddr(ip)
    except socket.herror: pass # ignore. Nothing to do.

    hostname = "unknown" # default host name.
    if results != "" and results != []:
        hostname = results[0] # keep only the host name.
    return hostname

def arping(filepath, arpit, ip_range, timeout=7): # need to use multithreading here
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=timeout)

    for req, res in ans:
        ip = res.getlayer(ARP).psrc
        mac = res.getlayer(Ether).src
        name = resolve_host_name(ip) # try to get the host name.
        with open(filepath, "a") as hostsFile:
            hostsFile.write("{} | {} | {}\n".format(ip, mac, name))


        if os.path.isfile(arpit):
            with open(arpit, "r+") as spoofit:
                if ip not in spoofit.read():
                    spoofit.write(ip + "\n")
        if not os.path.exists(arpit):
            print("Creating it.. ")
            open(arpit, "w")
            with open(arpit, "r+") as spoofit:
                if ip not in spoofit.read():
                    spoofit.write(ip + "\n")


