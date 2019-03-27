#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.general import getIpv4
from capturePkt.networkProtocol import NetworkProtocol


class IPv4(NetworkProtocol):
    IPv4Fields = (
        'Version', 'Header Length', 'Type of Service(DSCP)',
        'Type of Service(ECN)', 'Total Length', 'Identification',
        'Reversed bit', 'Don\'t Fragment', 'More Fragments', 'Fragment Offset',
        'Time To Live (TTL)', 'Protocol', 'Header Checksum', 'Source address',
        'Destination address')

    def __init__(self, raw_data):
        ip = unpack('!B B H H H B B H 4s 4s', raw_data[:20])
        self.version = ip[0] >> 4
        self.ihl = (ip[0] & 0xf) * 4
        self.tosDSCP = ip[1] >> 2
        self.tosECN = ip[1] & 3
        self.totalLength = ip[2]
        self.identification = ip[3]
        flag = ip[4] >> 13
        self.reserved = '1 set' if flag & 4 else '0 (not set)'
        self.donotFragment = '1 (DF)' if flag & 2 else '0 (not set)'
        self.moreFragments = '1 (MF)' if flag & 1 else '0 (not set)'
        self.fragmentOffset = ip[4] & 0x1fff
        self.ttl = ip[5]
        self.protocol = ip[6]
        # self.headerChecksum = str(ip[7]) + ' (' + str(hex(ip[7])) + ')'
        self.headerChecksum = '0x{:04x} ({})'.format(ip[7], ip[7])
        self.srcAddr = getIpv4(ip[8])
        self.destAddr = getIpv4(ip[9])

    def getFields(self):
        return IPv4.IPv4Fields

    def getParses(self):
        parses = (
            self.version, self.ihl, self.tosDSCP, self.tosECN, self.totalLength,
            self.identification, self.reserved, self.donotFragment,
            self.moreFragments, self.fragmentOffset, self.ttl, self.protocol,
            self.headerChecksum, self.srcAddr, self.destAddr)
        return parses
