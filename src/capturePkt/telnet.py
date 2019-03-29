#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class Telnet(NetworkProtocol):
    TelnetFields = ()

    def __init__(self, packet):
        telnet = unpack()

    def getFields(self):
        return Telnet.TelnetFields

    def getParses(self):
        parses = ()
        return parses
