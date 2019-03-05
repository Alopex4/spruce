#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import subprocess
from functools import namedtuple

import netifaces
from PyQt5 import QtWidgets
from PyQt5 import QtGui

from shineMainWindow import ShineMainWindow
from scanThread import ScanThread


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
        self.actionNetJSON.triggered.connect(self.netJsonExport)
        self.actionNetPlain.triggered.connect(self.netPlainExport)

        self.rangeButton.clicked.connect(
            lambda: self.scanLanNet(self.rangeLineEdit.text()))
        self.maskButton.clicked.connect(
            lambda: self.scanLanNet(self.maskLineEdit.text()))

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
            5. Export Menu active
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

        # Task 5
        # Export menu active
        self.menu_export.setEnabled(True)
        self.menuNetwork_info.setEnabled(True)

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

    def netJsonExport(self):
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

    def netPlainExport(self):
        """ 
            Format the network information thought JSON format
            File --> export --> networkInfo --> Plain text
        """
        saveFileName = self._exportFmtTpl('save network txt file',
                                          'plain text files(*.txt)', '.txt')
        if saveFileName:
            fieldNames = [
                'Interface name', 'IP address', 'Mac address', 'Vendor',
                'Gateway IP address', 'Gateway Mac address', 'Gateway Vendor'
            ]
            fieldDatas = [
                self.inetName, self.ipAddr, self.macAddr, self.vendor,
                self.gwIpAddr, self.gwMacAddr, self.gwVendor
            ]
            netwokInfo = tuple(zip(fieldNames, fieldDatas))
            with open(saveFileName, 'w') as plainFile:
                for itmes in netwokInfo:
                    plainFile.writelines('{key}: {value}\n'.format(
                        key=itmes[0], value=itmes[1]))

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

    def scanLanNet(self, scanTarget):
        """ 
            Store a nodesList data
            Scan thread work to scan Lan network
            Scan thread signal mapping
            When the scan parameter is wrong, emit tips message
        """

        self.nodeItems = []
        self.node = namedtuple('ItemNode',
                               ['ipAddr', 'macAddr', 'vendor', 'sort'])
        localNode = self.node(self.ipAddr, self.macAddr, self.vendor, 'local')
        self.nodeItems.append(localNode)

        self.scanWorker = ScanThread(self.inetName, scanTarget, self.macAddr,
                                     self.gwIpAddr, self.node, self.nodeItems)

        self.scanWorker.finishSignal[bool, str].connect(self.notifyRelatePanel)
        self.scanWorker.finishSignal[bool].connect(self.notifyRelatePanel)
        self.scanWorker.warnSignal.connect(self.scanWarnMessage)
        self.scanWorker.updateSignal.connect(self.scanNodeInsert)
        self.scanWorker.start()

    def scanWarnMessage(self, title, warningTips):
        """ Display scan Warning message """

        QtWidgets.QMessageBox.warning(self, title, warningTips)

    def notifyRelatePanel(self, finish, scanTarget=None):
        """
            Notify the scan panel/scan tab that the scan process is begin or finish 
            Clear the listNode, append scan method name

            status --> False --> begin
            status --> True --> finish
                begin:
                    clear the nodeList 
                    progressBar begin loop
                    lock button/lineEdit

                finish:
                    progressBar finish loop
                    unlock button/lineEdit
        """

        if scanTarget:
            if '-' in scanTarget:
                scanMethod = 'range scan'
            else:
                scanMethod = 'mask scan'
            self.scanDock.setWindowTitle('{}: {}'.format(
                'Scan Panel', scanMethod))

        self.scanDock.setEnabled(True)
        if not finish:
            self.scanProgressBar.setMaximum(0)
            self.scanProgressBar.setMaximum(0)
            self.scanProgressBar.setValue(0)

            self.rangeButton.setEnabled(False)
            self.rangeLineEdit.setEnabled(False)
            self.maskButton.setEnabled(False)
            self.maskLineEdit.setEnabled(False)
            self.nodeListWidget.clear()

        else:
            self.scanProgressBar.setMaximum(100)
            self.scanProgressBar.setMinimum(100)
            self.scanProgressBar.setValue(100)

            self.rangeButton.setEnabled(True)
            self.rangeLineEdit.setEnabled(True)
            self.maskButton.setEnabled(True)
            self.maskLineEdit.setEnabled(True)

    def scanNodeInsert(self, nodesList):
        """ 
            Insert the scanning nodes to table 
            1. Assign nodelist to nodeItems
            2. Traverse  all the nodeItems
        """

        self.nodeItems = nodesList

        for node in nodesList:
            Item = QtWidgets.QListWidgetItem()
            Item.setText('{} ({})'.format(node.vendor[:10], node.ipAddr))
            nodeIcon = self._selectIco(node.sort)
            icoFile = '{}/{}'.format('..', nodeIcon)
            Item.setIcon(QtGui.QIcon(icoFile))
            self.nodeListWidget.addItem(Item)

        print(self.nodeItems)

    def _selectIco(self, sort):
        """ Via node sort to select ico file"""

        if sort == 'local':
            icoFileName = 'local.ico'
        elif sort == 'gateway':
            icoFileName = 'gateway.ico'
        else:
            icoFileName = 'remote.ico'
        return icoFileName
