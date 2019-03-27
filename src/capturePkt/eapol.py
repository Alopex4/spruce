#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class EAPOL(NetworkProtocol):
    TypeDict = {0x00: '0x00 EAP Packet', 0x01: '0x01 Start',
                0x02: '0x02 Logoff', 0x03: '0x03 Key'}
    EAPOLFields = ('Version', 'Type', 'Length')

    def __init__(self, packet):
        eapol = unpack('!B B H', packet[:4])
        self.version = eapol[0]
        self.type = EAPOL.TypeDict.get(eapol[1])
        self.length = eapol[2]

    def getFields(self):
        return EAPOL.EAPOLFields

    def getParses(self):
        parses = (self.version, self.type, self.length)
        return parses
