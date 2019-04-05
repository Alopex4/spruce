#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from src.capturePkt.general import getIpv4, getIdentifier
from src.capturePkt.networkProtocol import NetworkProtocol
from src.capturePkt.ipv4 import IPv4


class PPPoES(NetworkProtocol):
    PPPoeSFields = (
        'Version', 'Type', 'Code', 'Session-ID', 'Payload Length', 'Tag Info')

    Tags = {0x0021: '0x0021 IP data', 0xc021: '0xc021 LCP data',
            0xc023: '0xc023 PAP data', 0x8021: '0x8021 NCP data',
            0x8057: '0x8057 IPv6 Data'}
    Codes = {0x01: '0x01 Configure-Request', 0x02: 'Configure-Ack',
             0x03: 'Configure-Nak', 0x04: 'Configure-Reject',
             0x05: 'Terminate-Request', 0x06: 'Terminate-Ack',
             0x07: 'Reject', 0x08: 'Protocol-Reject', 0x09: 'Echo-Request',
             0x0a: 'Echo-Reply', 0x0b: 'Discard-Request'}
    PaPCodes = {0x01: '0x01 Authenticate-Request',
                0x02: '0x02 Authenticate-Ack'}

    SeparateFmt = '----!Next! ({}) !Next!----'
    PPPoeSHeader = 8

    def __init__(self, packet):
        self.extendParse = tuple()
        self.extendField = tuple()
        self.separate = tuple()

        ppp = unpack('!B B H H H', packet[:PPPoES.PPPoeSHeader])
        self.version = ppp[0] >> 4
        self.type = ppp[0] & 0x0f
        self.code = '0x00 Session data' if ppp[1] == 0 else ppp[1]
        self.sessionID = '0x{:04x}'.format(ppp[2])
        self.length = ppp[3]
        self.tagInfo = PPPoES.Tags.get(ppp[4], 'Unknown data')
        self.remainParse(packet[PPPoES.PPPoeSHeader:])

    def remainParse(self, packet):
        field = tuple()
        parse = tuple()

        if '0x0021' in self.tagInfo:
            # IP
            ipv4 = IPv4(packet)
            field = ipv4.getFields()
            parse = ipv4.getParses()
            self.separate = (PPPoES.SeparateFmt.format('IP'),)
        else:
            refineData = self._prepareParse(packet)
            if '0xc021' in self.tagInfo:
                field, parse = self._lcpParse(refineData)
                self.separate = (PPPoES.SeparateFmt.format('IPCP'),)
            elif '0xc023' in self.tagInfo:
                field, parse = self._papParse(refineData)
                self.separate = (PPPoES.SeparateFmt.format('PAP'),)
            elif '0x8021' in self.tagInfo:
                field, parse = self._ncpParse(refineData)
                self.separate = (PPPoES.SeparateFmt.format('NCP'),)
            elif '0x8057' in self.tagInfo:
                field, parse = self._ipv6cpParse(refineData)
                self.separate = (PPPoES.SeparateFmt.format('IPv6CP'),)

        self.extendField = self.separate + field
        self.extendParse = self.separate + parse

    @staticmethod
    def _prepareParse(packet):
        remain = unpack('!B B H', packet[:4])
        code = PPPoES.Codes.get(remain[0], 'Unknown')
        identifier = '0x{:02x}'.format(remain[1])
        length = remain[2]
        packet = packet[4:]
        optLen = length - 4
        return packet, code, identifier, length, optLen

    @staticmethod
    def _lcpParse(refineData):
        xfield = tuple()
        xparse = tuple()
        packet, code, identifier, length, optLen = refineData

        if length == 18:
            remainNext = unpack('!2x H 2x H 2x 4s', packet[:optLen])
            maxReceive = remainNext[0]
            authenProt = '0x{}'.format(hex(remainNext[1]))
            magicNum = '0x{}'.format(remainNext[2].hex())

            xfield = (
                'Maximu Receive Unit', 'Authentication Protocol',
                'Magic Number')
            xparse = (maxReceive, authenProt, magicNum)
        elif length == 16:
            remainNext = unpack('!12s', packet)
            data = remainNext[0].decode('utf-8')

            xfield = ('Data',)
            xparse = (data,)
        elif length == 14:
            remainNext = unpack('!2x H 2x 4s', packet[:optLen])
            maxReceive = remainNext[0]
            magicNum = '0x{}'.format(remainNext[1].hex())

            xfield = ('Maximu Receive Unit', 'Magic Number')
            xparse = (maxReceive, magicNum)
        elif length == 8:
            remainNext = unpack('!4s', packet[:optLen])
            magicNum = '0x{}'.format(remainNext[0].hex())

            xfield = ('Magic Number',)
            xparse = (magicNum,)
        elif length == 6:
            remainNext = unpack('!H', packet[:optLen])
            reject = 'IPv6 control protocol ' + ' (' + hex(remainNext[0]) + ')'

            xfield = ('Reject Protocol',)
            xparse = (reject,)

        field = ('Code', 'Identifier', 'Length') + xfield
        parse = (code, identifier, length) + xparse
        return field, parse

    @staticmethod
    def _papParse(refineData):
        xfield = tuple()
        xparse = tuple()
        packet, code, identifier, length, optLen = refineData
        lengthFmt = '!{}s'

        if '0x01' in code:
            peerIDLen = packet[0]
            packet = packet[1:]

            peerIDRaw, *_ = unpack(lengthFmt.format(peerIDLen),
                                   packet[:peerIDLen])
            peerID = peerIDRaw.decode('utf-8')
            packet = packet[peerIDLen:]

            pwLen = packet[0]
            packet = packet[1:]
            pwRaw, *_ = unpack(lengthFmt.format(pwLen), packet[:pwLen])
            pw = pwRaw.decode('utf-8')

            xfield = (
                'Peer ID Length', 'Peer ID', 'Password Length', 'Password')

            xparse = (peerIDLen, peerID, pwLen, pw)

        elif '0x02' in code:
            msgLen = packet[0]
            packet = packet[1:]
            msgRaw, *_, = unpack(lengthFmt.format(msgLen), packet[:msgLen])
            msg = msgRaw.decode('utf-8')

            xfield = ('Message Length', 'Message')
            xparse = (msgLen, msg)

        field = ('Code', 'Identifier', 'Length') + xfield
        parse = (code, identifier, length) + xparse
        return field, parse

    @staticmethod
    def _ncpParse(refineData):
        xfield = tuple()
        xparse = tuple()
        packet, code, identifier, length, optLen = refineData

        if length == 10:
            ipAddrRaw, *_ = unpack('!2x 4s', packet[:optLen])
            ipAddr = getIpv4(ipAddrRaw)
            xfield = ('IP Address',)
            xparse = (ipAddr,)
        elif length == 22:
            ipAddrRaw, priDnsRaw, secDnsRaw = unpack('!2x 4s 2x 4s 2x 4s',
                                                     packet[:optLen])
            ipAddr = getIpv4(ipAddrRaw)
            priDns = getIpv4(priDnsRaw)
            secDns = getIpv4(secDnsRaw)
            xfield = (
                'IP Address', 'Primary DNS Server IP',
                'Secondary DNS Server IP')
            xparse = (ipAddr, priDns, secDns)

        field = ('Code', 'Identifier', 'Length') + xfield
        parse = (code, identifier, length) + xparse
        return field, parse

    @staticmethod
    def _ipv6cpParse(refineData):
        xfield = tuple()
        xparse = tuple()
        packet, code, identifier, length, optLen = refineData

        if length == 14:
            interfaceRaw, *_ = unpack('!2x 8s', packet[:optLen])
            interface = getIdentifier(interfaceRaw)
            xfield = ('Interface Identifier',)
            xparse = (interface,)

        field = ('Code', 'Identifier', 'Length') + xfield
        parse = (code, identifier, length) + xparse
        return field, parse

    def getParses(self):
        parses = (self.version, self.type, self.code, self.sessionID,
                  self.length, self.tagInfo) + self.extendParse
        return parses

    def getFields(self):
        fields = PPPoES.PPPoeSFields + self.extendField
        return fields
