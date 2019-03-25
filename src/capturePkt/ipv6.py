#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.general import getIpv6
from capturePkt.networkProtocol import NetworkProtocol


class IPv6(NetworkProtocol):
    ipv6Fields = (
        'Version', 'Traffic Class', 'Flow Label', 'Payload with Length',
        'Next Header', 'Hop Limit', 'Source Address', 'Destination Address')

    def __init__(self, pkt):
        ip = unpack('!I H B B 16s 16s', pkt[:40])
        self.version = ip[0] >> 28
        self.traffic = (ip[0] & 0x0ff00000) >> 20
        self.flow = self.getFlowLabel(ip[0] & 0x000fffff)
        self.payload = ip[1]
        self.nextHead = ip[2]
        self.hopLimit = ip[3]
        self.srcAddr = getIpv6(ip[4])
        self.dstAddr = getIpv6(ip[5])

    def getFlowLabel(self, flow):
        return str(flow) + ' (' + str(hex(flow)) + ')'

    def getFields(self):
        return IPv6.ipv6Fields

    def getParses(self):
        parses = (
            self.version, self.traffic, self.flow, self.payload, self.nextHead,
            self.hopLimit, self.srcAddr, self.dstAddr)
        return parses
