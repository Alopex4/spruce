#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from re import findall

# Unknow Layer
from capturePkt.networkProtocol import NetworkProtocol

# Link layer
from capturePkt.general import formatAssistant
from capturePkt.ethernet import Ethernet
from capturePkt.ipv6 import IPv6

# Network layer
from capturePkt.ipv4 import IPv4
from capturePkt.arp import ARP
from capturePkt.pppoed import PPPoED
from capturePkt.pppoes import PPPoES
from capturePkt.eapol import EAPOL

# Transport or extend layer
from capturePkt.icmp import ICMP
from capturePkt.igmp import IGMP
from capturePkt.udp import UDP
from capturePkt.tcp import TCP
from capturePkt.icmpv6 import ICMPv6
from capturePkt.hopopt import HOPOPT

# Application layer
from capturePkt.ntp import NTP
from capturePkt.domain import Domain
from capturePkt.telnet import Telnet
from capturePkt.publicApp import PublicApp


class CookedPacket:
    # Global variable
    LINK = 0
    INTERNET = 1
    TRANSPORT_EXTEND = 2
    APPLICATION = 3

    separator = '+-' * 11 + '+\n'
    initialText = '|' + ' ' * 4 + 'lack of data!' + ' ' * 4 + '|\n'
    initStr = separator + initialText + separator

    # Internet protocol mapping class
    InternetMap = {'Unknown': NetworkProtocol, 'ip': IPv4, 'arp': ARP,
                   'rarp': ARP, 'ipv6': IPv6, 'pppoe-d': PPPoED,
                   'pppoe-s': PPPoES, 'eapol': EAPOL}

    # TransExtend protocol mapping class
    TransExtendMap = {'Unknown': NetworkProtocol, 'icmp': ICMP, 'igmp': IGMP,
                      'udp': UDP, 'tcp': TCP, 'ipv6-icmp': ICMPv6,
                      'hopopt': HOPOPT}

    # Application protocol mapping class
    AppMap = {'Unknown': NetworkProtocol, 'domain': Domain, 'telnet': Telnet,
              'ssh': PublicApp, 'http': PublicApp, 'https': PublicApp,
              'mdns': Domain, 'nbns': Domain, 'ftp': PublicApp,
              'ftp-data': PublicApp, 'smtp': PublicApp, 'ntp': NTP,
              'pop3': PublicApp, 'snmp': PublicApp}

    def __init__(self, packet):
        self.packet = packet
        self.linkLayer = CookedPacket.initStr
        self.interLayer = CookedPacket.initStr
        self.transLayer = CookedPacket.initStr
        self.appLayer = CookedPacket.initStr
        self.rawDecode = CookedPacket.initStr
        self.utfDecode = CookedPacket.initStr
        self.cooking()

    def cooking(self):
        """ Cook the package to parse it ~"""

        # Cook link protocol
        link = Ethernet(self.packet.pktData[:14])
        linkField = link.getFields()
        linkParse = link.getParses()
        self.linkLayer = formatAssistant('ethernet', linkField, linkParse)
        ethHeaderLen = 14

        # Cook internet protocol
        try:
            internetProt = self.packet.pktProtStack[CookedPacket.INTERNET]
        except IndexError:
            pass
        else:
            interField, interParse = self.cookLayer(internetProt,
                                                    CookedPacket.InternetMap,
                                                    self.packet.pktData[
                                                    ethHeaderLen:])
            self.interLayer = formatAssistant(internetProt, interField,
                                              interParse)

        # Cook transport protocol or internet extend
        try:
            transProt = self.packet.pktProtStack[CookedPacket.TRANSPORT_EXTEND]
        except IndexError:
            pass
        else:
            if internetProt == 'pppoe-s':
                pppoeHeaderLen = 8
            else:
                pppoeHeaderLen = 0

            if internetProt == 'ipv6':
                ipHeaderLen = 40
                if self.packet.pktProtStack[
                    CookedPacket.TRANSPORT_EXTEND] == 'HOPOPT':
                    ipHeaderLen = 48
            else:
                ipHeaderLen = (self.packet.pktData[
                                   14 + pppoeHeaderLen] & 15) * 4

            internetHeaderLen = ethHeaderLen + pppoeHeaderLen + ipHeaderLen
            transExtendField, transExtendParse = self.cookLayer(transProt,
                                                                CookedPacket.TransExtendMap,
                                                                self.packet.pktData[
                                                                internetHeaderLen:])
            self.transLayer = formatAssistant(transProt, transExtendField,
                                              transExtendParse)

        # Cook application protocol
        try:
            appProt = self.packet.pktProtStack[CookedPacket.APPLICATION]
        except IndexError:
            pass
        else:
            if transProt == 'udp':
                transHeaderLen = 8
            elif transProt == 'tcp':
                transHeaderLen = (self.packet.pktData[
                                      internetHeaderLen + 12] >> 4) * 4
                # print(transHeaderLen)
                # print(self.packet.pktLen)
            appHeaderLen = internetHeaderLen + transHeaderLen
            # print(self.packet.pktData[appHeaderLen:])
            # print(appHeaderLen)
            if self.packet.pktData[appHeaderLen:]:
                appField, appParse = self.cookLayer(appProt,
                                                    CookedPacket.AppMap,
                                                    self.packet.pktData[
                                                    appHeaderLen:])
                self.appLayer = formatAssistant(appProt, appField, appParse)

        # decode prepare
        rawData = self.packet.pktData.hex()
        rawData = findall(r'.{2}', rawData)
        rawData.extend([''] * 48)

        # hex packet decode
        hexData = ' '.join(rawData)
        hexData = findall(r'.{24}', hexData)
        hexField, hexParse = self._getDecodes(hexData)
        self.rawDecode = formatAssistant('Hex Format', hexField, hexParse)

        # utf-8 packet decode
        chCodes = []
        for ch in rawData:
            if ch:
                chCode = int(ch, base=16)
                if chCode > 33 and chCode < 126:
                    chCodes.append(chr(chCode))
                else:
                    chCodes.append('·')
            else:
                chCodes.append(ch)
        utfData = ' '.join(chCodes)
        utfData = findall(r'.{16}', utfData)
        utfField, utfParse = self._getDecodes(utfData)
        self.utfDecode = formatAssistant('UTF-8 Format', utfField, utfParse)

    @staticmethod
    def _getDecodes(decodeData):
        field = []
        parse = []
        for index, data in enumerate(zip(decodeData[0::2], decodeData[1::2])):
            if not any((data[0].strip(), data[1].strip())):
                break
            line = '0x{:04x}'.format(index)
            field.append(line)
            parse.append('{}  {}'.format(data[0], data[1]))
        return field, parse

    @staticmethod
    def cookLayer(prot, mapping, packet):
        # protClsss = mapping.get(prot, 'Unknow')
        # try:
        #     protObj = protClsss(packet)
        # except Exception as e:
        #     print(e)
        #     field = ('Protocol header',)
        #     parse = ('Unknow',)
        # else:
        #     field = protObj.getFields()
        #     parse = protObj.getParses()
        # finally:
        #     return field, parse

        # Test
        protClsss = mapping.get(prot, NetworkProtocol)
        protObj = protClsss(packet)
        field = protObj.getFields()
        parse = protObj.getParses()
        return field, parse
