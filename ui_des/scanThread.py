#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from PyQt5 import QtWidgets
from PyQt5 import QtCore
from scapy.all import srp, Ether, ARP, conf
conf.verb = 0


class ScanThread(QtCore.QThread):
    finishSignal = QtCore.pyqtSignal(bool)
    warnSignal = QtCore.pyqtSignal(str, str)
    updateSignal = QtCore.pyqtSignal(tuple)

    def __init__(self, inetName, scanTarget, parten=None):
        super().__init__(parten)
        self.name = inetName
        self.target = scanTarget

    def arpScanning(self):
        """ Use arp query to scan local active nodes """

        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target),
                timeout=0.2,
                iface=self.name,
                inter=0.002)
        except (OSError, ValueError):
            warningTips = 'Doubble check your parameter\nMark sure it is correct\n'
            title = 'Scan Warn!'
            self.warnSignal.emit(title, warningTips)
            storeMacIP = None
        else:
            for _, rcv in ans:
                mac = rcv.sprintf(r"%ARP.psrc%")
                ipaddr = rcv.sprintf(r"%Ether.src%")
                storeMacIP = (mac, ipaddr)
        return storeMacIP

    def warningEmit(self):
        """ Emit the warning Signal """

        warningTips = 'Doubble check your parameter\nMark sure it is correct\n'
        title = 'Scan Warn!'
        self.warnSignal.emit(title, warningTips)

    def run(self):
        """ 
            Override the start method to scan active hosts
            1. Emit finishSignal(False) --> lock the scan panel
            2. Begin to scaning host via arp packets querys
                * Parameter correct --> emit updateSignal(tuple) scan host data(ip, mac, vendor)
                * Parameter incorrect --> emit warnSignal(str) tips message
            3. Emit finishSignal(True) --> unlock the scan panel
        """

        macIpItem = {}
        self.finishSignal.emit(False)

        for _ in range(3):
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.target),
                    timeout=0.2,
                    iface=self.name,
                    inter=0.002)
            except (OSError, ValueError):
                self.warningEmit()
                break
            else:
                for _, rcv in ans:
                    mac = rcv.sprintf(r"%ARP.psrc%")
                    ipaddr = rcv.sprintf(r"%Ether.src%")
                    macIpItem[mac] = ipaddr

                print(macIpItem)

        self.finishSignal.emit(True)