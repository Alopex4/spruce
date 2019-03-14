# ！/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import socket
import struct

from capturePkt.general import getMacAddr, getIpv4


class RoughPacket:
    CST = 8 * 60 * 60

    def __init__(self, sec, usec, index, pkt):
        self.sec = sec
        self.usec = usec
        self.pktIndex = index
        self.pktData = pkt
        self.pktSrc = 'Unknow'
        self.pktDst = 'Unknow'
        self.pktProt = 'Unknow'
        self.roughCook()

    def roughCook(self):
        """
            Rough process the packet
            * set time --> pktTime
            * set length --> pktLen
            * set source, destination address (ip precede over mac)
            * set protocol
        """

        # Set packet time
        cstSec = self.sec + RoughPacket.CST
        pktDate = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(cstSec))
        pktUsec = str(self.usec)[:3]
        self.pktTime = pktDate + pktUsec

        # Set packet length
        self.pktLen = len(self.pktData)

        # Get address
        # if protocol --> 0x0800 --> get ip
        # else --> get mac
        print(self.pktData)
        prototype, *_ = struct.unpack('!H', self.pktData[12:14])
        if prototype == 0x0800:
            self.pktProt = 'IP'
            srcIp, dstIp = struct.unpack('!4s 4s', self.pktData[26:34])
            self.pktSrc = getIpv4(srcIp)
            self.pktDst = getIpv4(dstIp)
        elif prototype == 0x0806:
            self.pktProt = 'ARP'
            dstMac, srcMac = struct.unpack('!6s 6s', self.pktData[:12])
            self.pktDst = getMacAddr(dstMac)
            self.pktSrc = getMacAddr(srcMac)
        elif prototype == 0x8863 or prototype == 0x8864:
            self.pktProt = 'PPPoE'
            pass

        # Get protocol type
        if self.pktProt == 'IP':
            self.ipHeaderLen = (self.pktData[14] & 15) * 4
            self.ipProt = int(self.pktData[23])

    def __str__(self):
        # fmt = 'pktIndex: {}\npktTime: {}\npktLen: {}\npktProt: {}\npktStr:{}\npktDst:{}\n'
        # return fmt.format(self.pktIndex, self.pktTime, self.pktLen,
        #                   self.pktProt, self.pktSrc, self.pktDst)
        fmt = 'headerLen: {}, ipProt: {}'
        return fmt.format(self.ipHeaderLen, self.ipProt)
