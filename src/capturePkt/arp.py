#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from src.capturePkt.general import getMacAddr, getIpv4
from src.capturePkt.networkProtocol import NetworkProtocol


class ARP(NetworkProtocol):
    ARPFields = ('Hard Type', 'Protocol Type', 'Hardware Address len',
                 'Protocol Address Len', 'Operation', 'Sender Ethernet Addr',
                 'Sender IP Addr', 'Target Ethernet Addr', 'Target IP Addr')

    def __init__(self, packet):
        arpHead = unpack('! H H B B H 6s 4s 6s 4s', packet[:28])
        self.hardType = arpHead[0]
        self.protType = '0x{:04x}'.format(arpHead[1])
        self.hardAddrLen = str(arpHead[2]) + ' (Bytes)'
        self.protAddrLen = str(arpHead[3]) + ' (Bytes)'
        self.op = self.defineOp(arpHead[4])
        self.sendEtheAddr = getMacAddr(arpHead[5])
        self.sendIPAddr = getIpv4(arpHead[6])
        self.targetEtheAddr = getMacAddr(arpHead[7])
        self.targetIPAddr = getIpv4(arpHead[8])

    def defineOp(self, opkey):
        opDict = {1: '1 (ARP request)', 2: '2 (ARP reply)',
                  3: '3 (RARP request)', 4: '4 (RARP reply)'}
        return opDict.get(opkey)

    def getFields(self):
        return ARP.ARPFields

    def getParses(self):
        parses = (
            self.hardType, self.protType, self.hardAddrLen, self.protAddrLen,
            self.op, self.sendEtheAddr, self.sendIPAddr, self.targetEtheAddr,
            self.targetIPAddr)
        return parses
