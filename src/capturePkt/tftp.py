#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from src.capturePkt.general import hexToASCII
from src.capturePkt.networkProtocol import NetworkProtocol


class TFTP(NetworkProtocol):
    TFTPFields = ('Option Code', 'Data')
    opcodeDir = {1: '1 Read request (RRQ)',
                 2: '2 Write request (WRQ)',
                 3: '3 Data (DATA)',
                 4: '4 Acknowledgment (ACK)',
                 5: '5 Error (ERROR)',
                 }

    def __init__(self, packet):
        tftp = unpack('!H', packet[:2])
        self.opcode = TFTP.opcodeDir[tftp[0]]
        self.data = hexToASCII(packet[2:], 20)

    def getFields(self):
        return TFTP.TFTPFields

    def getParses(self):
        parses = (self.opcode, self.data)
        return parses
