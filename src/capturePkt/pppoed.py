#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class PPPoED(NetworkProtocol):
    PPPoeDFields = (
        'Version', 'Type', 'Code', 'Session-ID', 'Length', 'Payload',
        'PPPoeTag')

    def __init__(self, packet):
        pass
        # ppp = unpack('!')

    def getFields(self):
        return PPPoED.PPPoeDFields

    def getParses(self):
        return
