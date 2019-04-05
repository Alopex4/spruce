#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from src.capturePkt.networkProtocol import NetworkProtocol


class IGMP(NetworkProtocol):
    IGMPFields = ('Version', 'Max Resp Code', 'Checksum')

    typeDict = {0x11: 'Membership Query',
                0x12: 'IGMPv1 Membership Report',
                0x16: 'IGMPv2 Membership Report',
                0x22: 'IGMPv3 Membership Report',
                0x17: 'Leave Group'
                }

    def __init__(self, packet):
        igmp = unpack('!B B H', packet[:4])
        self.type = IGMP.typeDict.get(igmp[0], 'Unknown')
        self.maxResp = igmp[1]
        self.checksum = '0x{:04x}'.format(igmp[2])

    def getFields(self):
        return IGMP.IGMPFields

    def getParses(self):
        parses = (self.type, self.maxResp, self.checksum)
        return parses
