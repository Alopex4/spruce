#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Link layer
from capturePkt.general import formatAssistant
from capturePkt.ethernet import Ethernet
from capturePkt.ipv6 import IPv6

# Network layer
from capturePkt.ipv4 import IPv4
from capturePkt.arp import ARP
from capturePkt.pppoed import PPPoED


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
    InternetMap = {'Unknow': None, 'ip': IPv4, 'arp': ARP, 'rarp': ARP,
                   'ipv6': IPv6, 'pppoe-d': PPPoED}

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

        # Cook internet protocol
        try:
            internetProt = self.packet.pktProtStack[CookedPacket.INTERNET]
        except IndexError:
            pass
        else:
            interField, interParse = self.cookLayer(internetProt,
                                                    CookedPacket.InternetMap,
                                                    self.packet.pktData[14:])
            self.interLayer = formatAssistant(internetProt, interField,
                                              interParse)

        # Cook transport protocol or internet extend
        try:
            transProt = self.packet.pktProtStack[CookedPacket.TRANSPORT_EXTEND]
        except IndexError:
            pass
        else:
            pass

        # Cook application protocol
        try:
            appProt = self.packet.pktProtStack[CookedPacket.APPLICATION]
        except IndexError:
            pass
        else:
            pass

    @staticmethod
    def cookLayer(prot, mapping, packet):
        protClsss = mapping.get(prot, 'Unknow')
        try:
            protObj = protClsss(packet)
        except Exception as e:
            print(e)
            field = ('Protocol header',)
            parse = ('Unknow',)
        else:
            field = protObj.getFields()
            parse = protObj.getParses()
        finally:
            return field, parse
