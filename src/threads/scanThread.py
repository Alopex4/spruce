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

    def __init__(self, inetName, scanTarget, macAddr, gwIpAddr, node, nodeItem,
                 nicType):
        super().__init__()
        self.name = inetName
        self.target = scanTarget
        self.macAddr = macAddr
        self.gwIpAddr = gwIpAddr
        self.node = node
        self.nodeItems = nodeItem
        self.nicType = nicType

    def __del__(self):
        self.quit()
        self.wait()

    def warningEmit(self):
        """ Parameter invalid emit the warning Signal """

        warningTips = 'Doubble check your parameter\nMark sure it is correct\n'
        title = 'Scan Warn!'
        self.warnSignal.emit(title, warningTips)

    def run(self):
        """ 
            Override the start method to scan active hosts
            1. Emit finishSignal(False) --> let brightMainWIndow know about it
            2. Begin to scaning host via arp packets querys
                * Parameter correct --> emit updateSignal(tuple)
                    updateSignal contain (mac, ip, )
                * Parameter incorrect --> emit warnSignal(str) tips message
            3. Emit finishSignal(True) --> let brightMainWIndow know about it
        """

        macSet = set()
        scanFail = False

        for times in range(1, 7):
            try:
                ans, _ = srp(
                    Ether(src=self.macAddr, dst="ff:ff:ff:ff:ff:ff") / ARP(
                        hwsrc=self.macAddr, pdst=self.target),
                    timeout=0.2,
                    iface=self.name,
                    inter=0.002)

            except (OSError, ValueError):
                self.warningEmit()
                scanFail = True
                break
            else:
                for _, rcv in ans:
                    ipaddr = rcv.sprintf(r"%ARP.psrc%")
                    mac = rcv.sprintf(r"%Ether.src%")

                    if times == 1:
                        self.finishSignal[bool, str].emit(False, self.target)
                        self.nodeItems.append(self._addingNode(mac, ipaddr))
                        macSet.add(mac)

                    if (times != 1) and (mac not in macSet):
                        self.nodeItems.append(self._addingNode(mac, ipaddr))
                        macSet.add(mac)

        # print(self.nodeItem)
        if (not scanFail and len(self.nodeItems) > 1) or self.nicType == 'ppp':
            self.updateSignal.emit(self.nodeItems)
        self.finishSignal[bool].emit(True)

    def _addingNode(self, mac, ipaddr):
        """ Generate adding node info"""

        node = self.node(ipaddr, mac, self._macQueryVendor(mac),
                         self._defineNodeType(ipaddr))
        return node

    def _defineNodeType(self, ipaddr):
        """ Define what node type(sort) it is"""

        if ipaddr == self.gwIpAddr:
            return 'gateway'
        else:
            return 'remote'

    def _macQueryVendor(self, macAddr):
        """ 
            Via a Mac address to query the vendor 
            OUI file head:
            Registry, Assignment, Organization Name, Organization Address
        """

        macOui = macAddr[:8].replace(':', '').upper()
        csvFileLoc = '{}/{}'.format('static/', 'oui.csv')
        with open(csvFileLoc, 'r') as csvFile:
            ouiReader = csv.reader(csvFile, delimiter=',')
            for row in ouiReader:
                if macOui in row:
                    return row[2]
            return '**Vendor not fond**'
