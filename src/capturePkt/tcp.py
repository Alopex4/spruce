#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from src.capturePkt.networkProtocol import NetworkProtocol


class TCP(NetworkProtocol):
    TCPFields = (
        'Source Port Number', 'Destination Port Number', 'Sequence Number',
        'Acknowledgment number', 'Header Length', 'Reserved', 'Flags',
        '    URG', '    ACK', '    PSH', '    RST', '    SYN', '    FIN',
        'Window size', 'Checksum', 'Urgent Pointer')

    optionDict = {1: 'No-Operation',
                  2: 'Maximum Segment Size',
                  3: 'Window Scale',
                  4: 'SACK Permitted',
                  5: 'SACK',
                  6: 'Echo (obsoleted by option 8)',
                  7: 'Echo Reply (obsoleted by option 8)',
                  8: 'Timestamps',
                  9: 'Partial Order Connection Permitted (obsolete)',
                  10: 'Partial Order Service Profile (obsolete)',
                  11: 'CC (obsolete)',
                  12: 'CC.NEW (obsolete)',
                  13: 'CC.ECHO (obsolete)',
                  14: 'TCP Alternate Checksum Request (obsolete)',
                  15: 'TCP Alternate Checksum Data (obsolete)',
                  16: 'Skeeter',
                  17: 'Bubba',
                  18: 'Trailer Checksum Option',
                  19: 'MD5 Signature Option (obsoleted by option 29)',
                  20: 'SCPS Capabilities',
                  21: 'Selective Negative Acknowledgements',
                  22: 'Record Boundaries',
                  23: 'Corruption experienced',
                  24: 'SNAP',
                  25: 'Unassigned (released 2000-12-18)',
                  26: 'TCP Compression Filter',
                  27: 'Quick-Start Response',
                  28: 'User Timeout Option (also, other known unauthorized use)',
                  29: 'TCP Authentication Option (TCP-AO)',
                  30: 'Multipath TCP (MPTCP)',
                  31: 'Reserved (known unauthorized use without proper IANA assignment)',
                  32: 'Reserved (known unauthorized use without proper IANA assignment)',
                  33: 'Reserved (known unauthorized use without proper IANA assignment)',
                  34: 'TCP Fast Open Cookie',
                  }

    def __init__(self, packet):
        self.packet = packet
        tcp = unpack('!H H I I H H H H', self.packet[:20])
        self.srcPort = tcp[0]
        self.dstPort = tcp[1]
        self.seqNumber = tcp[2]
        self.ackNumber = tcp[3]
        self.headerLen = (tcp[4] >> 12) * 4
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
        self.extendField = tuple()
        self.extendParse = tuple()

        if self.headerLen > 20:
            self.remainParse()

    def remainParse(self):
        optTotalLen = self.headerLen - 20
        readLen = 0
        self.packet = self.packet[20:]
        self.extendField = ('Options (Extend TCP header)',)
        self.extendParse = ('--------',)
        while readLen < optTotalLen:
            option = TCP.optionDict.get(self.packet[0], 'Unknown')
            if option == 'No-Operation':
                length = 1
            else:
                length = self.packet[1]
            self.extendField = self.extendField + ('    Option', '    Length')
            self.extendParse = self.extendParse + (
                option, str(length) + ' (Bytes)')
            readLen += length
            self.packet = self.packet[length:]

    def getFields(self):
        return TCP.TCPFields + self.extendField

    def getParses(self):
        parses = (self.srcPort, self.dstPort, self.seqNumber, self.ackNumber,
                  self.headerLen, self.reserved, self.flags, self.urg, self.ack,
                  self.psh, self.rst, self.syn, self.fin, self.windowLen,
                  self.checksum, self.urgentPointer) + self.extendParse
        return parses
