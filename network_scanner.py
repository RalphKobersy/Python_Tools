#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="ip", help="IP to scan")
    options= parser.parse_args()
    if options.ip is None:
        print("[!] Please enter a range of IP to scan")
    return options

def scan(ip):
    #creating arp request
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    full_arp_request = broadcast/arp_request

    #sending the request
    answered = scapy.srp(full_arp_request, timeout=1, verbose=False)[0] #custom ether

    clients_list = []

    for element in answered:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list

def print_clients(list_of_clients):
    print("IP\t\t\tMAC Address\n--------------------------------------")
    for client in list_of_clients:
        print(client["ip"] + "\t\t" + client["mac"])


option = get_arguments()
scan_results = scan(option.ip)
print_clients(scan_results)

