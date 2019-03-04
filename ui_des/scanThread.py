#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv

from PyQt5 import QtWidgets
from PyQt5 import QtCore
from scapy.all import srp, Ether, ARP, conf
conf.verb = 0


class ScanThread(QtCore.QThread):

    finishSignal = QtCore.pyqtSignal([bool, str], [bool])
    warnSignal = QtCore.pyqtSignal(str, str)
    updateSignal = QtCore.pyqtSignal(list)

    def __init__(self, inetName, scanTarget, gwIpAddr):
        super().__init__()
        self.name = inetName
        self.target = scanTarget
        self.gwIpAddr = gwIpAddr

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

        macSet = set()
        macIpItem = []
        times = 1

        for _ in range(6):
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
                    ipaddr = rcv.sprintf(r"%ARP.psrc%")
                    mac = rcv.sprintf(r"%Ether.src%")
                    macSet.add(mac)

                    if times == 1:
                        self.finishSignal[bool, str].emit(False, self.target)
                        macIpItem.append(self._addingNode(mac, ipaddr))

                    if (times != 1) and (mac not in macSet):
                        print('hello')
                        macIpItem.append(self._addingNode(mac, ipaddr))

                times += 1
        print(macIpItem)
        self.finishSignal[bool].emit(True)

    def _addingNode(self, mac, ipaddr):
        """ Generate adding node info"""

        node = (mac, ipaddr, self._macQueryVendor(mac),
                self._defineNodeType(ipaddr))
        return node

    def _defineNodeType(self, ipaddr):
        """ Define what node type it is"""

        if ipaddr == self.gwIpAddr:
            return 'Gateway'
        else:
            return 'Other host'

    def _macQueryVendor(self, macAddr):
        """ 
            Via a Mac address to query the vendor 
            OUI file head:
            Registry, Assignment, Organization Name, Organization Address
        """

        macOui = macAddr[:8].replace(':', '').upper()
        with open('oui.csv', 'r') as csvFile:
            ouiReader = csv.reader(csvFile, delimiter=',')
            for row in ouiReader:
                if macOui in row:
                    return row[2]
            return 'None'