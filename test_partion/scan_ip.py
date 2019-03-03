#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Scan the local network ips and mac
"""

from scapy.all import srp, Ether, ARP, conf

interface = "wlp5s0"
ips = "192.168.0.0/24"
# ips = "192.168.0.1-110"

print("Scaning ...")
# verbose info hide
conf.verb = 0
print("MAC - IP")
mac_ip = {}

for _ in range(6):
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ips),
        timeout=0.2,
        iface=interface,
        inter=0.002)

    for _, rcv in ans:
        mac = rcv.sprintf(r"%ARP.psrc%")
        ipaddr = rcv.sprintf(r"%Ether.src%")
        mac_ip[mac] = ipaddr

    print(len(mac_ip))
