#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import subprocess
from functools import namedtuple

import netifaces
from PyQt5 import QtWidgets
from PyQt5 import QtGui

from queryThread import QueryThread
from scanThread import ScanThread
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

        # Menu trigger action mapping
        self.actionNetCSV.triggered.connect(self.netCsvExport)
        self.actionNetJSON.triggered.connect(self.netJsonExport)
        self.actionNetPlain.triggered.connect(self.netPlainExport)
        self.actionLANCSV.triggered.connect(self.lanCsvExport)
        self.actionLANJSON.triggered.connect(self.lanJsonExport)
        self.actionLANPlain.triggered.connect(self.lanPlainExport)

        # Config panel button mapping
        self.refreshButton.clicked.connect(self.refreshBtnClick)
        self.rangeButton.clicked.connect(
            lambda: self.scanLanNet(self.rangeLineEdit.text()))
        self.maskButton.clicked.connect(
            lambda: self.scanLanNet(self.maskLineEdit.text()))
        self.sipButton.clicked.connect(self.queryIPInfo)

        # Scan panel button mapping
        self.nodeListWidget.itemSelectionChanged.connect(self.changAnalBtn)

    def refreshBtnClick(self):
        """
            Clicked the `refresh` button
            1. Acquire local netork work information
            2. Acquire gateway network information
            3. Display the information to the lineEdit
            4. Scan tab fill the lineEdit
            5. Export Menu active
        """

        # Acquire local info
        self._networkInfoAcq()

        # Accquire gateway info
        self._gatewayInfoAcq()

        # Display the info
        self._displayNetInfo()

        # Wire info to Scan tab
        self._fillScanTab()

        # Export menu active
        self.menu_export.setEnabled(True)
        self.menuNetwork_info.setEnabled(True)

    def _networkInfoAcq(self):
        """ 
            Acquire network information
                * Network Interface name
                * Network IP
                * Network MAC
                * Network Vendor --> via MAC and OUI.csv
                * Network Mask
        """

        self.inetName = netifaces.gateways()['default'][netifaces.AF_INET][1]
        if 'ppp' in self.inetName:
            self.nicType = 'ppp'
        else:
            self.nicType = 'original'

        self.ipAddr = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_INET][0]['addr']
        self.macAddr = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_LINK][0]['addr']
        self.netMask = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_INET][0]['netmask']
        self.vendor = self._macQueryVendor(self.macAddr)

    def _gatewayInfoAcq(self):
        """ 
            Acquire gateway information
                * Gateway IP
                * Gateway MAC
                * Gateway Vendor --> via MAC and OUI.csv
        """

        if self.nicType == 'original':
            self.gwIpAddr = netifaces.gateways()['default'][netifaces.AF_INET][
                0]
            cmd = "cat /proc/net/arp | grep '0x2' | xargs  | cut -d ' ' -f4"
            r = subprocess.check_output(cmd, shell=True)
            self.gwMacAddr = r.decode('utf-8').replace('\n', '')
            self.gwVendor = self._macQueryVendor(self.gwMacAddr)

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

    def _displayNetInfo(self):
        """ Display the network info to network tab lineEdit """

        self.nameLineEdit.setText(self.inetName)
        self.ipLineEdit.setText(self.ipAddr)
        self.macLineEdit.setText(self.macAddr)
        self.netmaskLineEdit.setText(self.netMask)
        self.vendorLineEdit.setText(self.vendor)

        self.gwIpLineEdit.setText(self.gwIpAddr)
        self.gwMacLineEdit.setText(self.gwMacAddr)
        self.gwVendorLineEdit.setText(self.gwVendor)

    def _fillScanTab(self):
        """ Fill out the scan tab """

        ipScanMask, ipScanRange = self._calScanParm(self.ipAddr, self.netMask)
        self.maskLineEdit.setText(ipScanMask)
        self.rangeLineEdit.setText(ipScanRange)

    def _calScanParm(self, ipAddr, netMask):
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

    # --------------
    # network export
    # --------------
    def netCsvExport(self):
        """ 
            Format the network information to csv format
            File --> export --> networkInfo --> Csv
        """

        networkData = []
        fieldNames = [
            'Interface name', 'IP address', 'Mac address', 'Vendor',
            'Gateway IP address', 'Gateway Mac address', 'Gateway Vendor'
        ]
        fieldDatas = [
            self.inetName, self.ipAddr, self.macAddr, self.vendor,
            self.gwIpAddr, self.gwMacAddr, self.gwVendor
        ]
        networkData.append(fieldNames)
        networkData.append(fieldDatas)

        self._fileExportTpl('save network csv file', 'csv files(*.csv)',
                            '.csv', networkData)

    def netJsonExport(self):
        """ 
            Format the network information to JSON format
            File --> export --> networkInfo --> Json
        """

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
        self._fileExportTpl('save network JSON file', 'csv files(*.json)',
                            '.json', networkInfo)

    def netPlainExport(self):
        """ 
            Format the network information to JSON format
            File --> export --> networkInfo --> Plain text
        """

        networkData = []
        fieldNames = [
            'Interface name', 'IP address', 'Mac address', 'Vendor',
            'Gateway IP address', 'Gateway Mac address', 'Gateway Vendor'
        ]
        fieldDatas = [
            self.inetName, self.ipAddr, self.macAddr, self.vendor,
            self.gwIpAddr, self.gwMacAddr, self.gwVendor
        ]
        networkData.append(fieldNames)
        networkData.append(fieldDatas)
        self._fileExportTpl('save network txt file', 'plain text files(*.txt)',
                            '.txt', networkData)

    # ----------
    # LAN export
    # ----------
    def lanCsvExport(self):
        """
            Format the LAN information to Csv format
            File --> export --> LAN info --> CSV
        """

        lanData = []
        fieldNames = ['ip address', 'mac address', 'vendor', 'sort']
        fieldDatas = self.nodeItems
        lanData.append(fieldNames)
        lanData.append(fieldDatas)

        self._fileExportTpl(
            'save network csv file',
            'csv files(*.csv)',
            '.csv',
            lanData,
            csvRows=True)

    def lanJsonExport(self):
        """
            Format the LAN information to Json format
            File --> export --> LAN info --> JSON
        """

        nodeDict = self.nodeItems
        nodeNames = ['ip address', 'mac address', 'vendor', 'sort']
        lanData = [
            dict(zip(nodeNames, nodeDict[i])) for i in range(len(nodeDict))
        ]

        self._fileExportTpl('save network JSON file', 'csv files(*.json)',
                            '.json', lanData)

    def lanPlainExport(self):
        """
            Format the LAN information to plain text format
            File --> export --> LAN info --> Plain
        """

        lanData = []
        fieldNames = ['ip address', 'mac address', 'vendor', 'sort']
        fieldDatas = self.nodeItems
        lanData.append(fieldNames)
        lanData.append(fieldDatas)

        self._fileExportTpl(
            'save network txt file',
            'plain text files(*.txt)',
            '.txt',
            lanData,
            txtRows=True)

    def _fileExportTpl(self,
                       dialogName,
                       fileFilter,
                       suffix,
                       data,
                       csvRows=False,
                       txtRows=False,
                       dirctory='.'):
        """
            General public file format export template
            According `fmt` save file in different way
        """

        saveFileName = self._exportFmtTpl(dialogName, fileFilter, suffix)

        if 'csv' in suffix:
            # data = [[fieldNames_list], [fieldDatas_list]]
            fieldNames, fieldDatas = data

            with open(saveFileName, 'w') as csvFile:
                writer = csv.DictWriter(csvFile, fieldnames=fieldNames)
                writer.writeheader()
                if csvRows:
                    saveRows = [
                        dict(zip(fieldNames, fieldDatas[i]))
                        for i in range(len(fieldDatas))
                    ]
                    writer.writerows(saveRows)
                else:
                    saveRow = dict(zip(fieldNames, fieldDatas))
                    writer.writerow(saveRow)

        elif 'json' in suffix:
            # data = JSON foramt
            with open(saveFileName, 'w') as jsonFile:
                json.dump(data, jsonFile, indent=4)

        elif 'txt' in suffix:
            # data = [[fieldNames_list], [fieldDatas_list]]
            fieldNames, fieldDatas = data
            with open(saveFileName, 'w') as plainFile:
                if txtRows:
                    saveData = [
                        tuple(zip(fieldNames, fieldDatas[i]))
                        for i in range(len(fieldDatas))
                    ]
                    for items in saveData:
                        for k, v in items:
                            plainFile.writelines('{key}: {value}\n'.format(
                                key=k, value=v))
                        plainFile.writelines('\n')
                else:
                    saveData = tuple(zip(fieldNames, fieldDatas))
                    for itmes in saveData:
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
            Reset the nodeListWidget current row avoid index out or range
            Store a nodesList data
            Scan thread work to scan Lan network
            Scan thread signal mapping
            When the scan parameter is wrong, emit tips message
        """

        self.nodeListWidget.setCurrentRow(-1)
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
        self.scanWorker.updateSignal.connect(self.scanNodesInsert)
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
                    menu export LAN disable
                    clear the nodeList 
                    protec tbutton
                finish:
                    protec tbutton
        """

        self.scanDock.setEnabled(True)
        self.menuProtect()
        if scanTarget:
            if '-' in scanTarget:
                scanMethod = 'range scan'
            else:
                scanMethod = 'mask scan'
            self.scanDock.setWindowTitle('{}: {}'.format(
                'Scan Panel', scanMethod))

        if not finish:
            self.menuLAN_info.setEnabled(False)
            self.nodeListWidget.clear()

        self.buttonProtect(finish)

    def menuProtect(self):
        """ Menu action protect """

        self.analysisButton.setText('analysis')
        self.analysisButton.setEnabled(False)
        self.action_Start.setEnabled(False)
        self.action_Stop.setEnabled(False)
        self.action_Restart.setEnabled(False)

    def buttonProtect(self, done):
        """ During the scaning process protect button """

        value = 100 if done else 0

        self.scanProgressBar.setMaximum(value)
        self.scanProgressBar.setMinimum(value)
        self.scanProgressBar.setValue(value)

        self.rangeButton.setEnabled(done)
        self.rangeLineEdit.setEnabled(done)
        self.maskButton.setEnabled(done)
        self.maskLineEdit.setEnabled(done)

    def scanNodesInsert(self, nodesList):
        """ 
            Insert the scanning nodes to table 
            1. Assign nodelist to nodeItems
            2. Traverse  all the nodeItems
            3. Active menu bar export --> LAN info
        """

        self.nodeItems = nodesList

        for node in nodesList:
            item = QtWidgets.QListWidgetItem()
            item.setText('{} ({})'.format(node.vendor[:10], node.ipAddr))
            nodeIcon = self._selectIco(node.sort)
            icoFile = '{}/{}'.format('..', nodeIcon)
            item.setIcon(QtGui.QIcon(icoFile))
            self.nodeListWidget.addItem(item)

        self.menuLAN_info.setEnabled(True)
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

    def queryIPInfo(self):
        """ Searh ip information(JSON format) and display it in the textEdit """

        self.sipTextEdit.clear()
        ip = self.sipLineEdit.text()

        self.queryWorker = QueryThread(ip)
        self.queryWorker.infoSignal.connect(self.queryInfo)
        self.queryWorker.finishSignal.connect(self.queryButton)
        self.queryWorker.jsonSignal.connect(self.queryDisplay)
        self.queryWorker.start()

        # Destroyed while thread is still running
        # Solution https://blog.csdn.net/suli_fly/article/details/21627535
        self.queryWorker.wait()

    def queryInfo(self, title, tips):
        """ When info raise show the message info """

        QtWidgets.QMessageBox.information(self, title, tips)

    def queryButton(self, done):
        """
            done --> False --> lock button
            done --> true --> unlock button
        """

        self.sipButton.setEnabled(done)

    def queryDisplay(self, jsonStr):
        """ Display the json text in textEdit """

        self.sipTextEdit.setText(jsonStr)

    def changAnalBtn(self):
        """ When nodeListWidget click change analysis button text """

        index = self.nodeListWidget.currentRow()
        itemAddr = self.nodeItems[index].ipAddr
        analBtnText = 'Analysis ({})'.format(itemAddr)
        self.analysisButton.setText(analBtnText)
        self.analysisButton.setEnabled(True)
        self.action_Start.setEnabled(True)
