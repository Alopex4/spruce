#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import scapy
import socket
from binascii import hexlify

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
# s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.bind(('wlp5s0', 0x0800))

while True:
    print(s.recvfrom(65535))