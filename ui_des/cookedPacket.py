#！/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore


class CookedPacket:
    def __init__(self, pktIndex, pkt):
        self.pktIndex = pktIndex
        self.pkt = pkt
        self.cooking()

    def cooking(self):
        print(self.pktIndex, self.pkt)
