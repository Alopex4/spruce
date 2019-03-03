#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import subprocess

import netifaces

from shineMainWindow import ShineMainWindow


class BrightMainWindow(ShineMainWindow):
    def __init__(self):
        super().__init__()
        self.signalSlotMap()
        self.refreshButton.click()

    def signalSlotMap(self):
        """
            Signal and slot mapping
            Widget communicate with each other relationship mapping
        """
        self.refreshButton.clicked.connect(self.refreshBtnClick)

    def refreshBtnClick(self):
        """
            Clicked the `refresh` button
            1. Acquire local netork work information
                * Network Interface name
                * Network IP
                * Network MAC
                * Network Vendor --> via MAC and OUI.csv
                * Network Mask
            2. Acquire gateway network information
                * Gateway IP
                * Gateway MAC
                * Gateway Vendor --> via MAC and OUI.csv
            3. Display the information to the lineEdit
            3. Emmit message --> `scan tab`
                * scan tab fill the lineEdit
        """

        # Task 1
        # Acquire local info
        self.inetName = netifaces.gateways()['default'][netifaces.AF_INET][1]
        self.ipAddr = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_INET][0]['addr']
        self.macAddr = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_LINK][0]['addr']
        self.netMask = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_INET][0]['netmask']
        self.vendor = self._macQueryVendor(self.macAddr)

        # Task 2
        # Accquire gateway info
        self.gwIpAddr = netifaces.gateways()['default'][netifaces.AF_INET][0]
        cmd = "cat /proc/net/arp | sed -n '2p' | xargs  | cut -d ' ' -f4"
        r = subprocess.check_output(cmd, shell=True)
        self.gwMacAddr = r.decode('utf-8')
        self.gwVendor = self._macQueryVendor(self.gwMacAddr)

        # Task 3
        # Display the info
        self.nameLineEdit.setText(self.inetName)
        self.ipLineEdit.setText(self.ipAddr)
        self.macLineEdit.setText(self.macAddr)
        self.netmaskLineEdit.setText(self.netMask)
        self.vendorLineEdit.setText(self.vendor)

        self.gwIpLineEdit.setText(self.gwIpAddr)
        self.gwMacLineEdit.setText(self.gwMacAddr)
        self.gwVendorLineEdit.setText(self.gwVendor)

        # Task 4
        # Wire info to Scan tab
        intIp = [int(x) for x in self.ipAddr.split('.')]
        intMask = [int(x) for x in self.netMask.split('.')]

        ipSegment = '.'.join([str(i & m) for i, m in zip(intIp, intMask)])
        maskBits = sum([bin(m).count('1') for m in intMask])
        ipMask = '{}/{}'.format(ipSegment, maskBits)
        ipRange = '{}-10'.format(ipSegment)

        self.maskLineEdit.setText(ipMask)
        self.rangeLineEdit.setText(ipRange)

        # self.maskLineEdit.setStyleSheet(
        #     "background-color: rgb(159, 232, 170); color: black;")
        # self.rangeLineEdit.setStyleSheet(
        #     "background-color: rgb(159, 232, 170); color: black")

    def _macQueryVendor(self, macAddr):
        """ Via a Mac address to query the vendor """

        macOui = macAddr[:8].replace(':', '').upper()
        with open('oui.csv', 'r') as csvFile:
            ouiReader = csv.reader(csvFile, delimiter=',')
            for row in ouiReader:
                if macOui in row:
                    vendor = row[2]
                    return vendor
            return 'None'
