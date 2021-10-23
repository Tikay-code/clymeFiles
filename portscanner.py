import sys
import socket
from scapy.all import *
import threading
import concurrent.futures
import time

print_lock = threading.Lock()


def otherWay(ip, port, filepath):
    scanner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    scanner.settimeout(1)
    try:
        scanner.connect((ip, port))
        scanner.close()
        with print_lock:
            with open(filepath, "a") as portsFile:
                portsFile.write("port {} is open\n".format(port))
    except:
        pass

def main(ip, filepath):
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(1025):
            executor.submit(otherWay, ip, port + 12, filepath)


