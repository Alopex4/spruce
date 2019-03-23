#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from capturePkt.ethernet import Ethernet


class CookedPacket:
    LINK = 0
    INTERNET = 1
    TRANSPORT_EXTEND = 2
    APPLICATION = 3

    separator = '+-' * 11 + '+\n'
    initialText = '|' + ' ' * 4 + 'Lack of data!' + ' ' * 4 + '|\n'
    initStr = separator + initialText + separator

    def __init__(self, packet):
        self.packet = packet
        self.linkLayer = CookedPacket.initStr
        self.interLayer = CookedPacket.initStr
        self.transLayer = CookedPacket.initStr
        self.appLayer = CookedPacket.initStr
        self.rawDecode = CookedPacket.initStr
        self.utfDecode = CookedPacket.initStr
        self.cooking()

    def _formatTitle(self, title):
        """ Format the layer title """

        separator = '+-' * 11 + '+\n'
        centerSpace = len(separator) - 3
        centerTitle = title.center(centerSpace)
        titleLine = '|{}|\n'.format(centerTitle)
        return separator + titleLine + separator

    def _formatParagraph(self, paraData):
        """ Format the header field and datas """

        containStr = ''
        separator = '+-' * 23 + '+\n'
        rightSpace = len(separator) - 3
        for k, v in paraData:
            item = '{}: {}'.format(k, v)
            itemSpace = item.ljust(rightSpace)
            itemLine = '|{}|\n'.format(itemSpace)
            containStr = containStr + itemLine
        return separator + containStr + separator

    def cooking(self):
        """ Cook the package to parse it ~"""

        # Cook link protocol
        link = Ethernet(self.packet.pktData[:14])
        linkField = 'Destination address: ', 'Source address: ', 'Ether Type: '
        linkParse = link.destMac, link.srcMac, link.proto
        self.linkLayer = self._cookAssistant('Ethernet', linkField, linkParse)

        # Cook internet protocol
        try:
            internetProt = self.packet.pktProtStack[CookedPacket.INTERNET]
        except IndexError:
            pass
        else:
            pass
            # interField, interParse = self.cookInternet(internetProt,
            #                                            self.pktData[14:])
            # self.interLayer = self._cookAssistant(internetProt, interField,
            #                                       interParse)

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

    def _cookAssistant(self, title, field, parse):
        """ Zip field and data together and return a foramt info"""

        layerData = tuple(zip(field, parse))
        header = self._formatTitle(title)
        contains = self._formatParagraph(layerData)
        return header + contains

    def cookInternet(prot, packet):
        if prot == 'ip':
            pass
        elif prot == 'arp':
            pass
        elif prot == 'ipv6':
            pass
        elif prot == 'pppoe-d':
            pass
        elif prot == 'pppoe-s':
            pass
        elif prot == 'eapol':
            pass
        elif prot == 'rarp':
            pass
        else:
            ('Protocol',), ('Unknow')
