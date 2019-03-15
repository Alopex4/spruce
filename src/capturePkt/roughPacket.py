# ！/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import socket
import struct

from capturePkt.general import getMacAddr, getIpv4


class RoughPacket:
    CST = 8 * 60 * 60
    # http://www.networksorcery.com/enp/protocol/802/ethertypes.htm
    EtherMapUpper = {0x0800: 'IP', 0x0806: 'ARP', 0x86DD: 'IPv6',
                     0x8863: 'PPoE (Discovery Stage)',
                     0x8864: 'PPPoE (PPP Session Stage)'}
    # https://www.wikiwand.com/en/List_of_IP_protocol_numbers
    IPMapUpper = {0x01: 'ICMP', 0x02: 'IGMP', 0x06: 'TCP', 0x11: 'UDP',
                  0x29: 'IPv6', 0x3A: 'IPv6-ICMP'}
    # https://www.wikiwand.com/en/List_of_TCP_and_UDP_port_numbers
    UDP_TCPMapUpper = {20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
                       25: 'SMTP', 53: 'Domain', 69: 'TFTP', 80: 'HTTP',
                       110: 'POP3', 123: 'NTP', 137: 'NBNS', 443: 'HTTPS', }

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
        self.pktProt = RoughPacket.EtherMapUpper.get(prototype, 'Unknow')
        if self.pktProt == 'IP':
            srcIp, dstIp = struct.unpack('!4s 4s', self.pktData[26:34])
            self.pktSrc = getIpv4(srcIp)
            self.pktDst = getIpv4(dstIp)
        elif self.pktProt == 'ARP':
            dstMac, srcMac = struct.unpack('!6s 6s', self.pktData[:12])
            self.pktDst = getMacAddr(dstMac)
            self.pktSrc = getMacAddr(srcMac)

        # IP protocol continue analysis upper protocol
        if self.pktProt == 'IP':
            ipHeaderLen = (self.pktData[14] & 15) * 4
            ipProt = int(self.pktData[23])
            self.pktProt = RoughPacket.IPMapUpper.get(ipProt, 'Unknow')

        # UDP/TCP protocol continue analysis application protocol
        if self.pktProt == 'UDP' or self.pktProt == 'TCP':
            # 14 --> Ethernet, ipHeaderLen, 2 --> source port
            rawSrcPort = (
                self.pktData[14 + ipHeaderLen + 0: 14 + ipHeaderLen + 2])
            srcPort, *_ = struct.unpack('!H', rawSrcPort)
            self.pktProt = RoughPacket.UDP_TCPMapUpper.get(srcPort,
                                                           'Unknow')
            if self.pktProt == 'Unknow':
                rawDstPort = (
                    self.pktData[14 + ipHeaderLen + 2: 14 + ipHeaderLen + 4])
                dstPort, *_ = struct.unpack('!H', rawDstPort)
                self.pktProt = RoughPacket.UDP_TCPMapUpper.get(dstPort,
                                                               'Unknow')
                print('srcPort', srcPort, 'dstPort', dstPort)

    def __str__(self):
        fmt = 'pktIndex: {}\npktTime: {}\npktLen: {}\npktProt: {}\npktSrc:{}\npktDst:{}\n'
        return fmt.format(self.pktIndex, self.pktTime, self.pktLen,
                          self.pktProt, self.pktSrc, self.pktDst)
        # fmt = 'headerLen: {}, ipProt: {}'
        # return fmt.format(self.ipHeaderLen, self.ipProt)
