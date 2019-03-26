#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


# http://jhengda.blogspot.com/2009/12/ppp-over-ethernet-pppoe.html
class PPPoED(NetworkProtocol):
    PPPoeDFields = (
        'Version', 'Type', 'Code', 'Session-ID', 'Payload Length', 'Tag Info')

    codeDict = {0x09: '0x09 Initiation Packet(PADI)',
                0x07: '0x07 Offer Packet(PADO)',
                0x19: '0x19 Session Request Packet(PADR)',
                0x65: '0x65 Session-confirmation Packet(PADS)',
                0xa7: '0xa7 Terminate Packet(PADO)'}

    tagTypes = {0x0000: '0x0000 End of list', 0x0101: '0x0101 Service-Name',
                0x0102: '0x0102 AC-Name', 0x0103: '0x0103 Host-uniq',
                0x0104: '0x0104 AC-cookie', 0x0105: '0x0105 Vendor-Specific',
                0x0110: '0x0110 Relay-session-Id',
                0x0201: '0x0201 Service-Name-Error',
                0x0202: '0x0202 AC-System-Error', 0x0203: 'Generic-Error'}

    PPPHeader = 6

    def __init__(self, packet):
        ppp = unpack('!B B H H', packet[:PPPoED.PPPHeader])
        self.version = ppp[0] >> 4
        self.type = ppp[0] & 0x0f
        self.code = PPPoED.codeDict[ppp[1]]
        self.sessionID = '0x{:04x}'.format(ppp[2])
        self.length = ppp[3]
        # 4 --> separate (0101 0000)
        data = packet[PPPoED.PPPHeader + 4:]
        self.tags = self.getTags(data)

    @staticmethod
    def getTags(data):
        # tag type, tag data length, tag data

        res = ''
        fmtTemp = '!{}s'

        while data:
            ppp = unpack('!H H', data[:4])
            tag = PPPoED.tagTypes[ppp[0]]
            if '0x0000' in tag:
                break
            tagDataLen = ppp[1]

            # cut the head
            data = data[4:]
            tagData, *_ = unpack(fmtTemp.format(tagDataLen), data[:tagDataLen])
            if '0x0102' in tag:
                tagData = tagData.decode('utf-8')
            else:
                tagData = '0x{}'.format(tagData.hex())
            data = data[tagDataLen:]
            res = res + tag + ' (' + tagData + ')\n'
        return res.rstrip('\n')

    def getFields(self):
        return PPPoED.PPPoeDFields

    def getParses(self):
        parses = (
            self.version, self.type, self.code, self.sessionID, self.length,
            self.tags)
        return parses
