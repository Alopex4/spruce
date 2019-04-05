# ！/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import socket
import struct

from PyQt5 import QtGui
from src.capturePkt.general import getMacAddr, getIpv4, getIpv6


class RoughPacket:
    CST = 8 * 60 * 60
    # http://www.networksorcery.com/enp/protocol/802/ethertypes.htm
    EtherMapUpper = {0x0800: 'IP', 0x0806: 'ARP', 0x86DD: 'IPv6',
                     0x8863: 'PPPoE-D', 0x8864: 'PPPoE-S', 0x888e: 'EAPOL',
                     0x8035: 'RARP'}
    # https://www.wikiwand.com/en/List_of_IP_protocol_numbers
    IPMapUpper = {0x00: 'HOPOPT', 0x01: 'ICMP', 0x02: 'IGMP', 0x06: 'TCP',
                  0x11: 'UDP', 0x29: 'IPv6', 0x3A: 'IPv6-ICMP'}
    # https://www.wikiwand.com/en/List_of_TCP_and_UDP_port_numbers
    UDP_TCPMapUpper = {20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
                       25: 'SMTP', 53: 'Domain', 67: 'DHCP', 68: 'DHCP',
                       69: 'TFTP', 80: 'HTTP', 110: 'POP3', 123: 'NTP',
                       137: 'NBNS', 443: 'HTTPS', 5353: 'MDNS', 162: 'SNMP',
                       161: 'SNMP'}
    ProtColorMap = {'ARP': QtGui.QColor(239, 83, 80, 255),
                    'IPv6': QtGui.QColor(171, 71, 188, 100),
                    'PPPoE-D': QtGui.QColor(236, 64, 122, 100),
                    'PPPoE-S': QtGui.QColor(236, 64, 122, 180),
                    'ICMP': QtGui.QColor(255, 238, 88, 100),
                    'IGMP': QtGui.QColor(255, 167, 38, 100),
                    'TCP': QtGui.QColor(66, 165, 245, 100),
                    'UDP': QtGui.QColor(102, 187, 106, 100),
                    'FTP-data': QtGui.QColor(85, 139, 47, 100),
                    'FTP': QtGui.QColor(158, 157, 36, 100),
                    'SSH': QtGui.QColor(96, 125, 139, 100),
                    'Telnet': QtGui.QColor(121, 85, 72, 100),
                    'SMTP': QtGui.QColor(255, 235, 59, 100),
                    'Domain': QtGui.QColor(46, 125, 50, 100),
                    'TFTP': QtGui.QColor(21, 101, 192, 100),
                    'HTTP': QtGui.QColor(128, 222, 234, 100),
                    'POP3': QtGui.QColor(173, 20, 87, 100),
                    'NTP': QtGui.QColor(255, 196, 0, 100),
                    'NBNS': QtGui.QColor(62, 39, 35, 100),
                    'HTTPS': QtGui.QColor(128, 222, 234, 200),
                    'DHCP': QtGui.QColor(255, 87, 34, 100),
                    'EAPOL': QtGui.QColor(46, 125, 50, 100),
                    'HOPOPT': QtGui.QColor(224, 64, 251, 100),
                    'RARP': QtGui.QColor(38, 166, 154, 100),
                    'MDNS': QtGui.QColor(173, 120, 77, 100),
                    'IPv6-ICMP': QtGui.QColor(146, 225, 50, 100),
                    'SNMP': QtGui.QColor(86, 175, 150, 100),
                    }

    supportPort = set()
    supportPort.update(['ip', 'ethernet'])
    supportPort.update(key.lower() for key in ProtColorMap.keys())

    def __init__(self, sec, usec, index, pkt):
        # print(index, pkt)
        self.sec = sec
        self.usec = usec
        self.pktIndex = index
        self.pktData = pkt
        self.pktSrc = 'Unknow'
        self.pktDst = 'Unknow'
        self.pktProt = 'Unknow'
        # Stack string
        self.pktStack = 'Unknow'
        # Stack data it should be list because the oder in under consider
        self.pktProtStack = ['ethernet']
        self.ethHeaderLen = 14
        self.pppExtendLen = 0
        self.ipHeaderLen = 0
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
        pktDate = time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime(cstSec))
        pktUsec = str(self.usec)[:3]
        self.pktTime = pktDate + pktUsec

        # Set packet length
        self.pktLen = len(self.pktData)

        # ----------
        # Link layer
        # ----------
        prototype, *_ = struct.unpack('!H', self.pktData[12:14])
        self.pktProt = RoughPacket.EtherMapUpper.get(prototype, 'Unknow')
        if self.pktProt == 'IP':
            srcIp, dstIp = struct.unpack('!4s 4s', self.pktData[26:34])
            self.pktSrc = getIpv4(srcIp)
            self.pktDst = getIpv4(dstIp)
        elif self.pktProt in ('IPv6', 'HOPOPT', 'IPv6-ICMP'):
            srcIpv6, dstIpv6 = struct.unpack('!16s 16s', self.pktData[22:54])
            self.pktSrc = getIpv6(srcIpv6)
            self.pktDst = getIpv6(dstIpv6)
        # elif self.pktProt in ('ARP', 'RARP', 'PPPoE-D', 'PPPoE-S'):
        else:
            dstMac, srcMac = struct.unpack('!6s 6s', self.pktData[:12])
            self.pktDst = getMacAddr(dstMac)
            self.pktSrc = getMacAddr(srcMac)

        self.appendProt(self.pktProt)

        # -------------
        # Network layer
        # -------------
        # IP protocol continue analysis upper protocol
        if self.pktProt == 'IP':
            self.ipHeaderLen = (self.pktData[14] & 15) * 4
            ipProt = int(self.pktData[23])
            self.pktProt = RoughPacket.IPMapUpper.get(ipProt, 'Unknow')

        # IPv6 protocol continue analysis upper protocol
        elif self.pktProt == 'IPv6':
            ipv6Prot = self.pktData[20]
            self.ipHeaderLen = 40
            self.pktProt = RoughPacket.IPMapUpper.get(ipv6Prot, 'Unknow')

        elif self.pktProt == 'PPPoE-S':
            pppProt = int(self.pktData[20:22].hex(), base=16)
            if pppProt == 0x0021:
                ipProt = int(self.pktData[31])
                self.pktProt = RoughPacket.IPMapUpper.get(ipProt, 'Unknow')
                self.ipHeaderLen = 20
                self.pppExtendLen = 8

        self.appendProt(self.pktProt)

        # ---------------
        # Transport layer
        # ---------------
        # UDP/TCP protocol continue analysis application protocol
        headerLen = self.ethHeaderLen + self.ipHeaderLen + self.pppExtendLen
        if self.pktProt == 'UDP':
            # 14 --> Ethernet, ipHeaderLen, 2 --> source port
            rawSrcPort = (self.pktData[headerLen + 0: headerLen + 2])
            srcPort, *_ = struct.unpack('!H', rawSrcPort)
            self.pktProt = RoughPacket.UDP_TCPMapUpper.get(srcPort,
                                                           'UDP')
            if self.pktProt == 'UDP':
                rawDstPort = (self.pktData[headerLen + 2: headerLen + 4])
                dstPort, *_ = struct.unpack('!H', rawDstPort)
                self.pktProt = RoughPacket.UDP_TCPMapUpper.get(dstPort,
                                                               'UDP')
        self.appendProt(self.pktProt)

        if self.pktProt == 'TCP':
            # 14 --> Ethernet, ipHeaderLen, 2 --> source port
            rawSrcPort = (self.pktData[headerLen + 0: headerLen + 2])
            srcPort, *_ = struct.unpack('!H', rawSrcPort)
            self.pktProt = RoughPacket.UDP_TCPMapUpper.get(srcPort, 'TCP')
            if self.pktProt == 'TCP':
                rawDstPort = (self.pktData[headerLen + 2: headerLen + 4])
                dstPort, *_ = struct.unpack('!H', rawDstPort)
                self.pktProt = RoughPacket.UDP_TCPMapUpper.get(dstPort,
                                                               'TCP')
        self.appendProt(self.pktProt)
        self.pktColor = RoughPacket.ProtColorMap.get(self.pktProt,
                                                     QtGui.QColor(224, 224, 224,
                                                                  255))

        # Generate package stack string
        stack = ''
        for prot in self.pktProtStack:
            decorProt = '[<< ' + prot + ' '
            stack = stack + decorProt
        self.pktStack = stack + len(self.pktProtStack) * '>>]'

    def getBriefPacket(self):
        """ Get the brief packet information """

        # briefPacket = NamedTuple('Brief Packet',
        #                          ['no', 'time', 'source', 'destination',
        #                           'protocol', 'length'])
        return (self.pktIndex, self.pktTime, self.pktSrc,
                self.pktDst, self.pktProt, self.pktLen, self.pktStack)

    def getColor(self):
        """ Get that packet color"""

        return self.pktColor

    def appendProt(self, prot):
        """ Append new item to pktProts list """

        prot = prot.lower()
        if prot not in self.pktProtStack:
            self.pktProtStack.append(prot)

    def __str__(self):
        """ For print function """

        fmt = 'pktIndex: {}\npktTime: {}\npktLen: {}\npktProt: {}\npktSrc:{}\npktDst:{}\npktProts:{}'
        return fmt.format(self.pktIndex, self.pktTime, self.pktLen,
                          self.pktProt, self.pktSrc, self.pktDst,
                          self.pktProtStack)
