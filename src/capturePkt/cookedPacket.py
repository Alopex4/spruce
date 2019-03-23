#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class CookedPacket:
    separator = '+-' * 11 + '+\n'
    tips = '|' + 4 * ' ' + 'Lack of data!' + 4 * ' ' + '|\n'
    emptyStr = separator + tips + separator

    def __init__(self, packet):
        self.packet = packet
        self.linkLayer = CookedPacket.emptyStr
        self.interLayer = CookedPacket.emptyStr
        self.transLayer = CookedPacket.emptyStr
        self.appLayer = CookedPacket.emptyStr
        self.rawDecode = CookedPacket.emptyStr
        self.hexDecode = CookedPacket.emptyStr



