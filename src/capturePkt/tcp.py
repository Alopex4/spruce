#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class TCP(NetworkProtocol):
    TCPFields = (
        'Source Port Number', 'Destination Port Number', 'Sequence Number',
        'Acknowledgment number', 'Header Length', 'Reserved', 'Flags',
        '    URG', '    ACK', '    PSH', '    RST', '    SYN', '    FIN',
        'Window size', 'Checksum', 'Urgent Pointer')

    def __init__(self, packet):
        tcp = unpack('!H H I I H H H H', packet[:20])
        self.srcPort = tcp[0]
        self.dstPort = tcp[1]
        self.seqNumber = tcp[2]
        self.ackNumber = tcp[3]
        self.headerLen = tcp[4] >> 12
        self.reserved = (tcp[4] & 0xfc) >> 6
        self.urg = 1 if (tcp[4] & 0x20) else 0
        self.ack = 1 if (tcp[4] & 0x10) else 0
        self.psh = 1 if (tcp[4] & 0x08) else 0
        self.rst = 1 if (tcp[4] & 0x04) else 0
        self.syn = 1 if (tcp[4] & 0x02) else 0
        self.fin = 1 if (tcp[4] & 0x01) else 0
        self.windowLen = tcp[5]
        flagStr = ('URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN')
        flagCode = (self.urg, self.ack, self.psh, self.rst, self.syn, self.fin)
        flags = [flag[0] for flag in zip(flagStr, flagCode) if all(flag)]
        self.flags = '/'.join(flags).upper()
        self.checksum = '0x{:04x} ({})'.format(tcp[6], tcp[6])
        self.urgentPointer = '0x{:04x} ({})'.format(tcp[7], tcp[7])

    def getFields(self):
        return TCP.TCPFields

    def getParses(self):
        parses = (self.srcPort, self.dstPort, self.seqNumber, self.ackNumber,
                  self.headerLen, self.reserved, self.flags, self.urg, self.ack,
                  self.psh, self.rst, self.syn, self.fin, self.windowLen,
                  self.checksum, self.urgentPointer)
        return parses
