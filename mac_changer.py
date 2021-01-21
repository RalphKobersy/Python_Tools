#!/usr/bin/env python

import subprocess
import optparse
import re

def change_mac_address(interface, new_mac):
    print("[+] Changing MAC address for {0} to {1}".format(interface, new_mac))

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

def get_args():
    parser = optparse.OptionParser()

    parser.add_option("-i", "--interface", dest="interface", help="Interface to change the MAC address")
    parser.add_option("-m", "--mac", dest="new_mac", help="New MAC address")

    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[!] Please specify the interface")
    elif not options.new_mac:
        parser.error("[!] Please specify the new MAC address")
    return options

def get_current_mac_address(interface):
    ifconfig_output = subprocess.check_output(["ifconfig", interface])
    ifconfig_mac_address = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_output))

    if ifconfig_mac_address:
        return ifconfig_mac_address.group(0)
    else:
        print("[!] Could not read MAC address")

options = get_args()

current_mac_address = get_current_mac_address(options.interface)
print("Current MAC -> {}".format(current_mac_address))

change_mac_address(options.interface, options.new_mac)

current_mac_address = get_current_mac_address(options.interface)
if current_mac_address == options.new_mac:
    print("[+] MAC address have been successfully changed to {}".format(current_mac_address))
else:
    print("[!] MAC address did not change.")