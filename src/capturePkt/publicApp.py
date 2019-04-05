#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from src.capturePkt.networkProtocol import NetworkProtocol
from src.capturePkt.general import hexToASCII


class PublicApp(NetworkProtocol):
    Fields = ('data',)

    def __init__(self, packet):
        self.data = hexToASCII(packet, 40)

    def getFields(self):
        return PublicApp.Fields

    def getParses(self):
        parses = (self.data,)
        return parses
