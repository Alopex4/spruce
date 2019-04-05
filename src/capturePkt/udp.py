#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from src.capturePkt.networkProtocol import NetworkProtocol


class UDP(NetworkProtocol):
    UDPFields = (
        'Source Port Number', 'Destination Port Number', 'Length', 'Checksum')

    def __init__(self, packet):
        udp = unpack('!H H H H', packet[:8])
        self.srcPort = udp[0]
        self.dstPort = udp[1]
        self.length = udp[2]
        self.checksum = '0x{:02x} ({})'.format(udp[3], udp[3])

    def getFields(self):
        return UDP.UDPFields

    def getParses(self):
        parses = (self.srcPort, self.dstPort, self.length, self.checksum)
        return parses
