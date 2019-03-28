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

    # https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
    OptionDict = {0: 'EOOL   - End of Options List',
                  1: 'NOP    - No Operation',
                  130: 'SEC    - Security',
                  131: 'LSR    - Loose Source Route',
                  68: 'TS     - Time Stamp',
                  133: 'E-SEC  - Extended Security',
                  134: 'CIPSO  - Commercial Security',
                  7: 'RR     - Record Route',
                  136: 'SID    - Stream ID',
                  137: 'SSR    - Strict Source Route',
                  10: 'ZSU    - Experimental Measurement',
                  11: 'MTUP   - MTU Probe',
                  12: 'MTUR   - MTU Reply',
                  205: 'FINN   - Experimental Flow Control',
                  142: 'VISA   - Experimental Access Control',
                  15: 'ENCODE - ???',
                  144: 'IMITD  - IMI Traffic Descriptor',
                  145: 'EIP    - Extended Internet Protocol',
                  82: 'TR     - Traceroute',
                  147: 'ADDEXT - Address Extension',
                  148: 'RTRALT - Router Alert',
                  149: 'SDB    - Selective Directed Broadcast',
                  150: '       - Unassigned (Released 18 October 2005)',
                  151: 'DPS    - Dynamic Packet State',
                  152: 'UMP    - Upstream Multicast Pkt.',
                  25: 'QS     - Quick-Start',
                  30: 'EXP    - RFC3692-style Experiment',
                  94: 'EXP    - RFC3692-style Experiment',
                  158: 'EXP    - RFC3692-style Experiment',
                  222: 'EXP    - RFC3692-style Experiment',
                  }

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
        self.extendFiled = tuple()
        self.extendParse = tuple()
        if self.ihl > 20:
            self.optionParse(raw_data[20:])

    def optionParse(self, pkt):
        remain = unpack('!B B', pkt[:2])
        optionType = remain[0]
        typeMeaning = IPv4.OptionDict[remain[0]]
        length = remain[1]
        self.extendFiled = ('OptionType', 'Type Meaning', 'Length')
        self.extendParse = (optionType, typeMeaning, length)

    def getFields(self):
        fields = IPv4.IPv4Fields + self.extendFiled
        return fields

    def getParses(self):
        parses = (self.version, self.ihl, self.tosDSCP, self.tosECN,
                  self.totalLength, self.identification, self.reserved,
                  self.donotFragment, self.moreFragments,
                  self.fragmentOffset, self.ttl, self.protocol,
                  self.headerChecksum, self.srcAddr,
                  self.destAddr) + self.extendParse
        return parses
