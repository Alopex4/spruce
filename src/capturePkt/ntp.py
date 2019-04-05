#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from struct import unpack

from src.capturePkt.networkProtocol import NetworkProtocol
from src.capturePkt.general import getIpv4


class NTP(NetworkProtocol):
    # http://www.networksorcery.com/enp/protocol/ntp.htm
    # https://xixiliguo.github.io/post/ntp/
    # http://bjtime.cn/info/view.asp?id=301
    NTPFields = (
        'Flags', '    Leap Indicator', '    Version', '    Mode', 'Stratum',
        'Poll Interval', 'Precision', 'Root Delay', 'Root Dispersion',
        'Reference clock identifier', 'Reference timestamp (UTC)',
        'Originate timestamp (UTC)', 'Receive timestamp (UTC)',
        'Transmit timestamp (UTC)')
    liDict = {0: '0 (No Warning)', 1: '1 (Last minute has 61 seconds)',
              2: '2 (Last minute has 59 seconds.)',
              3: '3 (Alarm condition, clock not synchronized.)'}
    modeDict = {0: '0 (Reserved)',
                1: '1 (Symmetric active)',
                2: '2 (Symmetric passive)',
                3: '3 (Client)',
                4: '4 (Server)',
                5: '5 (Broadcast)',
                6: '6 (NTP control message)',
                7: '6 (private use)',
                }
    stratumDict = {0: '0 (Unspecified)', 1: '1 (Primary reference'}
    JAN1970 = 0x83aa7e80

    def __init__(self, packet):
        ntp = unpack('!B B B B I I 4s I I I I I I I I', packet[:48])
        self.li = NTP.liDict.get(ntp[0] >> 6)
        self.version = (ntp[0] & 0x28) >> 3
        self.mode = NTP.modeDict.get(ntp[0] & 0x07)
        self.flag = '0x{:02x} ({})'.format(ntp[0], ntp[0])
        self.stratum = NTP.stratumDict.get(ntp[1], 'Secondary reference')
        self.poll = ntp[2]
        self.precision = '0x{:04x} ({})'.format(ntp[3], ntp[3])
        self.rootDelay = '0x{:04x} ({})'.format(ntp[4], ntp[4])
        self.rootDisp = '0x{:04x} ({})'.format(ntp[5], ntp[5])
        self.refer = self._getRefer(ntp[6])
        self.referenceTS = self._fromNTPToSystem(ntp[7], ntp[8])
        self.originateTS = self._fromNTPToSystem(ntp[9], ntp[10])
        self.receiveTS = self._fromNTPToSystem(ntp[11], ntp[12])
        self.transmitTS = self._fromNTPToSystem(ntp[13], ntp[14])

    def _getRefer(self, data):
        if '0' in self.stratum or '1' in self.stratum:
            return data.decode('utf-8')
        return getIpv4(data)

    def _fromNTPToSystem(self, sec, nsec):
        sysSec = sec - self.JAN1970
        sysNsec = nsec / (10 ** 6) * 1000000 / 0x100000000
        sysNsec = str(sysNsec).replace('.', '')
        sysDate = time.strftime("%Y-%m-%d %H:%M:%S ", time.gmtime(sysSec))
        fmt = '{}.{}'.format(sysDate.rstrip(), sysNsec)
        return fmt

    def getFields(self):
        return NTP.NTPFields

    def getParses(self):
        parses = (
            self.flag, self.li, self.version, self.mode, self.stratum,
            self.poll, self.precision, self.rootDelay, self.rootDisp,
            self.refer, self.referenceTS, self.originateTS, self.receiveTS,
            self.transmitTS)
        return parses
