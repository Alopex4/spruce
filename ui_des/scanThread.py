#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtWidgets
from PyQt5 import QtCore
from scapy.all import srp, Ether, ARP, conf
conf.verb = 0


class ScanThread(QtCore.QThread):
    warnSingle = QtCore.pyqtSignal(str, str)

    def __init__(self, inetName, scanTarget, parten=None):
        super().__init__(parten)
        self.name = inetName
        self.target = scanTarget

    def run(self):
        """ Overide the start method """

        storeMacIP = {}

        for _ in range(6):
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target),
                    timeout=0.2,
                    iface=self.name,
                    inter=0.002)
            except (OSError, ValueError):
                warningTips = 'Doubble check your parameter\nMark sure it is correct\n'
                title = 'Scan Warn!'
                self.warnSingle.emit(title, warningTips)
                break
            else:
                for _, rcv in ans:
                    mac = rcv.sprintf(r"%ARP.psrc%")
                    ipaddr = rcv.sprintf(r"%Ether.src%")
                    storeMacIP[mac] = ipaddr

                print(storeMacIP)