#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Link layer
from capturePkt.ethernet import Ethernet

# Network layer
from capturePkt.ipv4 import IPv4


class CookedPacket:
    # Global variable
    LINK = 0
    INTERNET = 1
    TRANSPORT_EXTEND = 2
    APPLICATION = 3

    separator = '+-' * 11 + '+\n'
    initialText = '|' + ' ' * 4 + 'Lack of data!' + ' ' * 4 + '|\n'
    initStr = separator + initialText + separator

    # Protocol mapping class
    InternetMap = {'ip': IPv4, 'Unknow': None, }

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
        self.linkLayer = self._cookAssistant('Ethernet', linkField, linkParse)

        # Cook internet protocol
        try:
            internetProt = self.packet.pktProtStack[CookedPacket.INTERNET]
        except IndexError:
            pass
        else:
            interField, interParse = self.cookLayer(internetProt,
                                                    CookedPacket.InternetMap,
                                                    self.packet.pktData[14:])
            self.interLayer = self._cookAssistant(internetProt, interField,
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

    def _cookAssistant(self, title, field, parse):
        """ Zip field and data together and return a foramt info"""

        layerData = tuple(zip(field, parse))
        header = self._formatTitle(title)
        contains = self._formatParagraph(layerData)
        return header + contains

    @staticmethod
    def _formatTitle(title):
        """ Format the layer title """

        separator = '+-' * 11 + '+\n'
        centerSpace = len(separator) - 3
        centerTitle = title.center(centerSpace)
        titleLine = '|{}|\n'.format(centerTitle)
        return separator + titleLine + separator

    @staticmethod
    def _formatParagraph(paraData):
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

    @staticmethod
    def cookLayer(prot, mapping, packet):
        protClsss = mapping.get(prot, 'Unknow')
        try:
            protObj = protClsss(packet)
        except Exception:
            field = ('Protocol header',)
            parse = ('Unknow',)
        else:
            field = protObj.getFields()
            parse = protObj.getParses()
        finally:
            return field, parse
