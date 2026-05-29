from scapy.all import *

def generate_http_traffic():
    packet = IP(dst="127.0.0.1")/TCP(dport=80)/Raw(load="GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
    send(packet, count=20)

if __name__ == "__main__":
    generate_http_traffic()
