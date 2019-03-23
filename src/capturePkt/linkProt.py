#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from capturePkt.general import getMacAddr


class Ethernet:
    def __init__(self, packet):
        dest, src, prototype = struct.unpack('! 6s 6s H', packet)
        self.destMac = getMacAddr(dest)
        self.srcMac = getMacAddr(src)
        self.proto = hex(prototype)
