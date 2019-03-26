#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol
from capturePkt.ipv4 import IPv4


class PPPoES(NetworkProtocol):
    PPPoeSFields = (
        'Version', 'Type', 'Code', 'Session-ID', 'Payload Length', 'Tag Info')

    PPPoESTag = {0x0021: '0x0021 IP data', 0xc021: '0xc021 LCP data',
                 0xc023: '0xc023 PAP data', 0x8021: '0x8021 NCP data',
                 0x8057: '0x8057 IPv6 Data'}

    separate = ('***! Protocol Separate !***',)
    PPPoeSHeader = 8

    def __init__(self, packet):
        self.extendParse = tuple()
        self.extendField = tuple()

        ppp = unpack('!B B H H H', packet[:PPPoES.PPPoeSHeader])
        self.version = ppp[0] >> 4
        self.type = ppp[0] & 0x0f
        self.code = '0x00 Session data' if ppp[1] == 0 else ppp[1]
        self.sessionID = '0x{:04x}'.format(ppp[2])
        self.length = ppp[3]
        self.tagInfo = PPPoES.PPPoESTag.get(ppp[4], 'Unknown data')
        self.remainParse(packet[PPPoES.PPPoeSHeader:])

    def remainParse(self, packet):
        if '0x0021' in self.tagInfo:
            ipv4 = IPv4(packet)
            field = ipv4.getFields()
            parse = ipv4.getParses()
        elif '0xc021' in self.tagInfo:
            remain = unpack('!B B H', packet[:4])
            code = 'Configuration Request (1)' if remain[
                                                      0] == 1 else 'Configuration ACK (2)'
            identifier = '0x{:02x}'.format(remain[1])
            length = remain[2]
            packet = packet[4:]
            optLen = length - 4
            if length == 18:
                remainNext = unpack('!2x H 2x H 2x 4s', packet[:optLen])
                maxReceive = remainNext[0]
                authenProt = '0x{}'.format(hex(remainNext[1]))
                magicNum = '0x{}'.format(remainNext[2].hex())
                field = ('Code', 'Identifier', 'Length', 'Maximu Receive Unit',
                         'Authentication Protocol', 'Magic Number')
                parse = (
                    code, identifier, length, maxReceive, authenProt, magicNum)
            elif length == 14:
                remainNext = unpack('!2x H 2x 4s', packet[:optLen])
                maxReceive = remainNext[0]
                magicNum = '0x{}'.format(remainNext[1].hex())
                field = ('Code', 'Identifier', 'Length', 'Maximu Receive Unit',
                         'Magic Number')
                parse = (code, identifier, length, maxReceive, magicNum)
            elif length == 8:
                remainNext = unpack('!4s', packet[:4])
                magicNum = '0x{}'.format(remainNext[0].hex())
                field = ('Code', 'Identifier', 'Length', 'Magic Number')
                parse = (code, identifier, length, magicNum)
            elif length == 6:
                remainNext = unpack('!H', packet[:2])
                reject = 'IPv6 control protocol ' + ' (' + hex(
                    remainNext[0]) + ')'
                field = ('Code', 'Identifier', 'Length', 'Reject Protocol')
                parse = (code, identifier, length, reject)
            else:
                field = ('Code', 'Identifier', 'Length')
                parse = (code, identifier, length)
        elif '0x8021' in self.tagInfo:
            pass

        self.extendField = PPPoES.separate + field
        self.extendParse = PPPoES.separate + parse

    def getParses(self):
        parses = (self.version, self.type, self.code, self.sessionID,
                  self.length, self.tagInfo) + self.extendParse
        return parses

    def getFields(self):
        fields = PPPoES.PPPoeSFields + self.extendField
        return fields
