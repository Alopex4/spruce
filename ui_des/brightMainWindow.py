#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import subprocess

from PyQt5 import QtWidgets
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
        self.actionNetCSV.triggered.connect(self.netCsvExport)
        self.actionNetJSON.triggered.connect(self.netJsonExpor)

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
            4. Scan tab fill the lineEdit
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
        self.gwMacAddr = r.decode('utf-8').replace('\n', '')
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
        ipScanMask, ipScanRange = self._scanParameter(self.ipAddr,
                                                      self.netMask)
        self.maskLineEdit.setText(ipScanMask)
        self.rangeLineEdit.setText(ipScanRange)

        # self.maskLineEdit.setStyleSheet(
        #     "background-color: rgb(159, 232, 170); color: black;")
        # self.rangeLineEdit.setStyleSheet(
        #     "background-color: rgb(159, 232, 170); color: black")

    def _scanParameter(self, ipAddr, netMask):
        """ 
            Generate the scan parameter 
            ipMask --> eg: 192.168.1.1/24
            ipRange --> eg: 192.168.1.0-10
        """

        intIpList = [int(x) for x in self.ipAddr.split('.')]
        intMaskList = [int(x) for x in self.netMask.split('.')]

        ipSegment = '.'.join(
            [str(i & m) for i, m in zip(intIpList, intMaskList)])
        maskBits = sum([bin(m).count('1') for m in intMaskList])
        ipMask = '{}/{}'.format(ipSegment, maskBits)
        ipRange = '{}-10'.format(ipSegment)
        return ipMask, ipRange

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

    def netCsvExport(self):
        """ 
            Format the network information thought csv format
            File --> export --> networkInfo --> Csv
        """

        saveFileName = self._exportFmtTpl('save network csv file',
                                          'csv files(*.csv)', '.csv')
        if saveFileName:
            with open(saveFileName, 'w') as csvFile:
                fieldNames = [
                    'Interface name', 'IP address', 'Mac address', 'Vendor',
                    'Gateway IP address', 'Gateway Mac address',
                    'Gateway Vendor'
                ]
                fieldDatas = [
                    self.inetName, self.ipAddr, self.macAddr, self.vendor,
                    self.gwIpAddr, self.gwMacAddr, self.gwVendor
                ]

                writer = csv.DictWriter(csvFile, fieldnames=fieldNames)
                writer.writeheader()
                writer.writerow(dict(zip(fieldNames, fieldDatas)))

    def netJsonExpor(self):
        """ 
            Format the network information thought JSON format
            File --> export --> networkInfo --> Json
        """
        saveFileName = self._exportFmtTpl('save network JSON file',
                                          'csv files(*.json)', '.json')
        if saveFileName:
            networkInfo = {
                'local': {
                    'Interface name': self.inetName,
                    'IP address': self.ipAddr,
                    'Mac address': self.macAddr,
                    'Vendor': self.vendor
                },
                'gateway': {
                    'IP address': self.gwIpAddr,
                    'Mac addres': self.gwMacAddr,
                    'Vendor': self.gwVendor
                }
            }
            with open(saveFileName, 'w') as jsonFile:
                json.dump(networkInfo, jsonFile, indent=4)

    def _exportFmtTpl(self, dialogName, fileFilter, suffix, dirctory='.'):
        """ 
            Menubar --> File --> export ---> ... 
            Export csv, json, plaint text format template 
        """

        # _ -> file type
        saveFileName, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, dialogName, dirctory, fileFilter)

        if saveFileName:
            if suffix not in saveFileName:
                saveFileName = saveFileName + suffix
        return saveFileName
