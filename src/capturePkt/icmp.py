#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime
from string import printable

from struct import unpack
from socket import ntohl

from src.capturePkt.networkProtocol import NetworkProtocol


class ICMP(NetworkProtocol):
    ICMPFields = ('Type', 'Code', 'Checksum', 'Message Type')

    MessageTypeDict = {0: {0: 'Echo reply'},
                       3: {0: 'Destination network unreachable',
                           1: 'Destination host unreachable',
                           2: 'Destination protocol unreachable',
                           3: 'Destination port unreachable',
                           4: 'Fragmentation required, and DF flag set',
                           5: 'Source route failed',
                           6: 'Destination network unknown',
                           7: 'Destination host unknown',
                           8: 'Source host isolated',
                           9: 'Network administratively prohibited',
                           10: 'Host administratively prohibited',
                           11: 'Network unreachable for ToS',
                           12: 'Host unreachable for ToS',
                           13: 'Communication administratively prohibited',
                           14: 'Host Precedence Violation',
                           15: 'Precedence cutoff in effect'},
                       5: {0: 'Redirect Datagram for the Network',
                           1: 'Redirect Datagram for the Host',
                           2: 'Redirect Datagram for the ToS & network',
                           3: 'Redirect Datagram for the ToS & host',
                           },
                       8: {0: 'Echo request (used to ping)'},
                       9: {0: 'Router Advertisement'},
                       10: {0: 'Router discovery/selection/solicitation'},
                       11: {0: 'TTL expired in transit',
                            1: 'Fragment reassembly time exceeded'},
                       12: {0: 'Pointer indicates the error',
                            1: 'Missing a required option',
                            3: 'Bad length'},
                       13: {0: 'Timestamp'},
                       14: {0: 'Timestamp reply'},
                       }

    def __init__(self, packet):
        self.icmp = unpack('!B B H', packet[:4])
        self.type = '0x{:02x} ({})'.format(self.icmp[0], self.icmp[0])
        self.code = '0x{:02x} ({})'.format(self.icmp[1], self.icmp[1])
        self.checksum = '0x{:04x}'.format(self.icmp[2])
        try:
            self.messageType = ICMP.MessageTypeDict.get(self.icmp[0]).get(
                self.icmp[1])
        except AttributeError:
            self.messageType = 'Unknown'

        self.extendField = tuple
        self.extendParse = tuple
        self.remainParse(packet[4:])

    def remainParse(self, packet):
        field = tuple()
        parse = tuple()

        if (self.icmp[0] == 0 or self.icmp[0] == 8) and (self.icmp[1] == 0):
            try:
                remainICMP = unpack('!H H L 4x', packet[:12])
            except Exception:
                pass
            else:
                dataFmt = '!{}s'
                identifer = remainICMP[0]
                sequence = remainICMP[1]
                timestamp = remainICMP[2]
                sequence = '0x{:04x} ({})'.format(sequence, sequence)
                timestamp = datetime.fromtimestamp(ntohl(timestamp))

                packet = packet[12:]
                data, *_ = unpack(dataFmt.format(len(packet)), packet)
                data = data.decode('utf-8', 'replace')
                data = list(filter(lambda x: x in printable, data))
                data = ''.join(data)
                field = (
                    'Identifier', 'Sequence Number', 'Timestamp CST', 'Data')
                parse = (
                    identifer, sequence, timestamp, data[:70] + '... (omit)')

        self.extendField = field
        self.extendParse = parse

    def getFields(self):
        return ICMP.ICMPFields + self.extendField

    def getParses(self):
        parses = (self.type, self.code, self.checksum, self.messageType)
        return parses + self.extendParse
