#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.general import getMacAddr
from capturePkt.networkProtocol import NetworkProtocol


class Ethernet(NetworkProtocol):
    EthernetFields = ('Destination Address', 'Source Address', 'Ether Tyep')

    def __init__(self, packet):
        eth = unpack('! 6s 6s H', packet)
        self.destMac = getMacAddr(eth[0])
        self.srcMac = getMacAddr(eth[1])
        self.proto = '0x{:04x}'.format(eth[2])

    def getFields(self):
        return Ethernet.EthernetFields

    def getParses(self):
        return (self.destMac, self.srcMac, self.proto)
