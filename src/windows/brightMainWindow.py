#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import json
import struct
import subprocess
from time import sleep
from copy import deepcopy
from functools import namedtuple
from datetime import datetime

import netifaces
import numpy as np
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5 import QtWidgets
from matplotlib.ticker import MaxNLocator

# Capture packet manager
from docutils.nodes import section

from capturePkt.roughPacket import RoughPacket
# Thread workers
from threads.queryThread import QueryThread
from threads.termsThread import TermsThread
from threads.scanThread import ScanThread
from threads.trafficThread import TrafficThread
from threads.poisonThread import PoisonThread
from threads.captureThread import CaptureThread
from threads.openThread import OpenThread
from threads.saveThread import SaveThread
from threads.searchThread import SearchThread
from threads.parseThread import ParseThread
# Menu open dialogs
from dialogs.shineDialog import ui_FilterDialog
from dialogs.shineDialog import Ui_NodeDialog
from dialogs.shineDialog import Ui_LoadDialog
from dialogs.shineDialog import Ui_StatisticDialog
from windows.shineMainWindow import ShineMainWindow


class BrightMainWindow(ShineMainWindow):
    # 60 * 60 * 8
    CST_time_zone = 28800
    iconDir = '../icon'
    netfieldNames = ['Interface name', 'IP address', 'Mac address', 'Vendor',
                     'Gateway IP address', 'Gateway Mac address',
                     'Gateway Vendor']
    lanFieldNames = ['ip address', 'mac address', 'vendor', 'sort']
    pktFieldNames = ['No', 'Time', 'Source', 'Destination', 'Protocol',
                     'Length',
                     'Stack']

    def __init__(self):
        super().__init__()
        self.variableInit()
        self.signalSlotMap()
        self.refreshButton.click()

    def variableInit(self):
        """ Initial the variable this window need to use """

        # Store network interface type
        self.nicType = 'original'
        self.inetNameAlias = ''

        # Store scan node
        self.node = namedtuple('ItemNode',
                               ['ipAddr', 'macAddr', 'vendor', 'sort'])
        self.nodeItems = []

        # Store network traffic info
        self.timestamps = []
        self.uploads = []
        self.downloads = []
        self.sents = []
        self.recvs = []

        # Store filter string
        self.filterDict = {'type': 'noncustom', 'filter': ''}

        # Store all the process packet
        self.rarePkts = []

        # Search package
        self.searchPkts = []

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
        self.actionPktCSV.triggered.connect(self.pktCsvExport)
        self.actionPktJSON.triggered.connect(self.pktJsonExport)
        self.actionPktPlain.triggered.connect(self.pktPlainExport)
        self.action_CtrlPan.triggered.connect(self.controlDock.setVisible)
        self.action_ScanPan.triggered.connect(self.scanDock.setVisible)
        self.action_Open.triggered.connect(self.showOpenFile)
        self.action_Save.triggered.connect(self.showSaveFile)
        self.action_Start.triggered.connect(self.analysisButton.click)
        self.action_Stop.triggered.connect(self.stopButton.click)
        self.action_Restart.triggered.connect(self.stopStart)
        self.action_IOflow.triggered.connect(self.ioFlowStats)
        self.action_Speed.triggered.connect(self.speedStats)
        self.action_Filter.triggered.connect(self.settingFilterDict)

        # Config panel button mapping
        self.refreshButton.clicked.connect(self.refreshBtnClick)
        self.rangeButton.clicked.connect(
            lambda: self.scanLanNet(self.rangeLineEdit.text()))
        self.rangeLineEdit.returnPressed.connect(self.rangeButton.click)

        self.maskButton.clicked.connect(
            lambda: self.scanLanNet(self.maskLineEdit.text()))
        self.maskLineEdit.returnPressed.connect(self.maskButton.click)

        self.sipButton.clicked.connect(self.queryIPInfo)
        self.sipLineEdit.returnPressed.connect(self.sipButton.click)

        self.termButton.clicked.connect(self.queryTerms)
        self.termLineEdit.returnPressed.connect(self.termButton.click)

        self.searchButton.clicked.connect(self.searchProt)
        self.searchLineEdit.returnPressed.connect(self.searchButton.click)

        # Dock close mapping
        self.controlDock.visibilityChanged.connect(
            self.action_CtrlPan.setChecked)
        self.scanDock.visibilityChanged.connect(self.action_ScanPan.setChecked)

        # Scan panel button mapping
        self.nodeListWidget.itemSelectionChanged.connect(self.changAnalBtn)
        self.nodeListWidget.itemDoubleClicked.connect(self.showNodeDialog)
        self.analysisButton.clicked.connect(self.analysisManage)
        self.stopButton.clicked.connect(self.stopManage)

        # Concise table mapping
        # Item select by mouse or arrow
        self.conciseInfoTable.itemSelectionChanged.connect(
            lambda: self.parsePacket(self.conciseInfoTable.currentRow()))

    def XWarning(self, title, warningTips):
        """ Display all type of  warning message """

        QtWidgets.QMessageBox.warning(self, title, warningTips,
                                      QtWidgets.QMessageBox.Yes)

    # --------------
    # refersh Button
    # --------------
    def refreshBtnClick(self):
        """
            Clicked the `refresh` button
            * Test the network connection
            1. Acquire local netork work information
            2. Acquire gateway network information
            3. Display the information to the lineEdit
            4. Scan tab fill the lineEdit
            5. Export Menu active
        """
        connect = self.networkStartUpCheck()
        if connect:
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
            self.inetNameAlias = self._getWiredNetName()
            self.macAddr = netifaces.ifaddresses(
                self.inetNameAlias)[netifaces.AF_LINK][0]['addr']
        else:
            self.macAddr = netifaces.ifaddresses(
                self.inetName)[netifaces.AF_LINK][0]['addr']

        self.ipAddr = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_INET][0]['addr']
        self.netMask = netifaces.ifaddresses(
            self.inetName)[netifaces.AF_INET][0]['netmask']
        self.vendor = self._macQueryVendor(self.macAddr)

    def _getWiredNetName(self):
        """
            Get wired network interface name (include 'en' or 'eth')
                * New style:
                    enp0s10:
                     v | |
                    en | |  -- ethernet
                       v |
                      p0 |  -- bus number (0)
                         v
                        s10 -- slot number (10)
                * Old style:
                    eth --> ethernet
        """

        interfaces = netifaces.interfaces()
        for ifName in interfaces:
            if 'en' in ifName:
                return ifName
            elif 'eth' in ifName:
                return ifName

    def _gatewayInfoAcq(self):
        """
            Acquire gateway information
                * Gateway IP
                * Gateway MAC
                * Gateway Vendor --> via MAC and OUI.csv
        """

        self.gwIpAddr = netifaces.gateways()['default'][netifaces.AF_INET][0]
        if self.nicType == 'original':
            cmd = "cat /proc/net/arp | grep '{}'| grep '{}' | xargs  | cut -d ' ' -f4".format(
                '0x2', self.gwIpAddr)
            r = subprocess.check_output(cmd, shell=True)
            self.gwMacAddr = r.decode('utf-8').replace('\n', '')
            self.gwVendor = self._macQueryVendor(self.gwMacAddr)
        elif self.nicType == 'ppp':
            self.gwMacAddr = '`ppp` link no gateway mac'
            self.gwVendor = '`ppp` link no gateway vendor'

    def _macQueryVendor(self, macAddr):
        """
            Via a Mac address to query the vendor
            OUI file head:
            Registry, Assignment, Organization Name, Organization Address
        """

        macOui = macAddr[:8].replace(':', '').upper()
        csvFileLoc = '{}/{}'.format('../static/', 'oui.csv')
        with open(csvFileLoc, 'r') as csvFile:
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
        fieldDatas = [
            self.inetName, self.ipAddr, self.macAddr, self.vendor,
            self.gwIpAddr, self.gwMacAddr, self.gwVendor
        ]
        networkData.append(BrightMainWindow.netfieldNames)
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
        self._fileExportTpl('save network JSON file', 'json files(*.json)',
                            '.json', networkInfo)

    def netPlainExport(self):
        """
            Format the network information to JSON format
            File --> export --> networkInfo --> Plain text
        """

        networkData = []
        fieldDatas = [
            self.inetName, self.ipAddr, self.macAddr, self.vendor,
            self.gwIpAddr, self.gwMacAddr, self.gwVendor
        ]
        networkData.append(BrightMainWindow.netfieldNames)
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
        fieldDatas = self.nodeItems
        lanData.append(BrightMainWindow.lanFieldNames)
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
        nodeNames = BrightMainWindow.lanFieldNames
        lanData = [
            dict(zip(nodeNames, nodeDict[i])) for i in range(len(nodeDict))
        ]

        self._fileExportTpl('save network JSON file', 'json files(*.json)',
                            '.json', lanData)

    def lanPlainExport(self):
        """
            Format the LAN information to plain text format
            File --> export --> LAN info --> Plain
        """

        lanData = []
        fieldDatas = self.nodeItems
        lanData.append(BrightMainWindow.lanFieldNames)
        lanData.append(fieldDatas)

        self._fileExportTpl(
            'save network txt file',
            'plain text files(*.txt)',
            '.txt',
            lanData,
            txtRows=True)

    # -------------
    # packet export
    # -------------
    def pktCsvExport(self):
        """
            Format the packet information to Csv format
            File --> export --> packet info --> Csv
        """

        pktData = []
        fieldDatas = self._getExportPkt()
        pktData.append(BrightMainWindow.pktFieldNames)
        pktData.append(fieldDatas)

        self._fileExportTpl(
            'save packet csv file',
            'csv files(*.csv)',
            '.csv',
            pktData,
            csvRows=True)

    def pktJsonExport(self):
        """
            Format the packet information to Json format
            File --> export --> packet info --> Json
        """

        pktList = self._getExportPkt()
        pktData = [
            dict(zip(BrightMainWindow.pktFieldNames, pktList[i])) for i in
            range(len(pktList))
        ]

        self._fileExportTpl('save packet JSON file', 'json files(*.json)',
                            '.json', pktData)

    def pktPlainExport(self):
        """
            Format the packet information to plain text format
            File --> export --> packet info --> Plain
        """

        pktData = []
        fieldDatas = self._getExportPkt()
        pktData.append(BrightMainWindow.pktFieldNames)
        pktData.append(fieldDatas)

        self._fileExportTpl(
            'save packet txt file',
            'plain text files(*.txt)',
            '.txt',
            pktData,
            txtRows=True)

    def _getExportPkt(self):
        """
            Get the export packet brief info
            * First check the searchPkts
            * Second check the rarePkts
                * All the pkt object get brief packet info
        """

        if self.searchPkts:
            copyObj = self.searchPkts
        else:
            copyObj = self.rarePkts
        exportPkts = deepcopy(copyObj)
        return [pkt.getBriefPacket() for pkt in exportPkts]

    # ---------------
    # export template
    # ---------------
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
            csvRows --> multi lines
            txtRows --> multi lines
        """

        saveFileName = self._exportFmtTpl(dialogName, fileFilter, suffix)

        if saveFileName:
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

    # ---------
    # Save file
    # ---------
    def showSaveFile(self):
        """
            Menubar --> File --> &save
            Save a file in disk, auto append --> .pcap
            * Set file name
            * Write to disk
            * disable `save` menu
        """

        saveFileName, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, 'save file', '.', "pcaket files (*.pcap)")

        if saveFileName:
            if '.pcap' not in saveFileName:
                saveFileName = saveFileName + '.pcap'
            self.writePcapFile(saveFileName)

        self.action_Save.setEnabled(False)

    def writePcapFile(self, filename):
        """
            Write the pcap data to the disk
            * write the header info
            * write the packet info
        """

        self.saveWorker = SaveThread(filename, self.rarePkts)
        if len(self.rarePkts) > 5000:
            self.saveWorker.started.connect(lambda: self.loadingWindow(True))
            self.saveWorker.finished.connect(lambda: self.loadingWindow(False))
        self.saveWorker.start()

    # ---------
    # open file
    # ---------
    def showOpenFile(self):
        """
            Menubar --> File --> &open
            show open file dialog get open file name(.pcap)
            * Get openFile name
            * Read header info define the file type
            * Clear the container
            * active the analysis widget(conciseTable, verboseTabs,decodeTabs)
            * Read file and cook the package
            * Show concise table meun
        """

        # _ --> file types
        openFileName, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 'open file', '.', "packet files (*.pcap)")
        if openFileName:
            verified = self._checkPcapFile(openFileName)
            if verified:
                self._readWidgetChange()
                self.readPacpFile(openFileName)
                self.menu_export.setEnabled(True)
                self.menuPackets_info.setEnabled(True)
                connect = self.networkStartUpCheck()
                if connect:
                    self.showTableMenu()
            else:
                title = 'Open waring'
                tips = 'Make sure your open file is `pacp` file'
                self.XWarning(title, tips)

    def _readWidgetChange(self):
        """ Read file widget change """

        self.rarePkts.clear()
        self.conciseInfoTable.setRowCount(0)
        self.conciseInfoTable.clearContents()
        self.conciseInfoTable.setEnabled(True)
        self.linkTab.setEnabled(True)
        self.interTab.setEnabled(True)
        self.transTab.setEnabled(True)
        self.appTab.setEnabled(True)
        self.linkTextEdit.setEnabled(True)
        self.linkTextEdit.setReadOnly(True)
        self.interTextEdit.setEnabled(True)
        self.interTextEdit.setReadOnly(True)
        self.transTextEdit.setEnabled(True)
        self.transTextEdit.setReadOnly(True)
        self.appTextEdit.setEnabled(True)
        self.appTextEdit.setReadOnly(True)

        self.verboseInfoTab.setEnabled(True)
        self.utfTab.setEnabled(True)
        self.rawTab.setEnabled(True)
        self.decodeInfoTab.setEnabled(True)
        self.searchButton.setEnabled(True)

        self.menu_protocol.setEnabled(True)
        self.menu_length.setEnabled(True)
        # self.menu_flow.setEnabled(True)

        self._resetTabs()

    def _checkPcapFile(self, fileName):
        """ Check whether it's a pcap file """

        with open(fileName, 'rb') as diskFile:
            header = diskFile.read(24)
            magic, majv, minv = struct.unpack('@I H H 16x', header)
            if magic == 0xa1b2c3d4 and majv == 2 and minv == 4:
                return True
            return False

    def readPacpFile(self, openFileName):
        """
            Read the pcap file generate the raraPkts
        """

        fileSize = os.path.getsize(openFileName)

        self.openWorker = OpenThread(openFileName, fileSize)
        self.openWorker.readSignal.connect(self.unpackPacket)
        # If file size gt 5M --> show waiting
        if fileSize > 5000000:
            self.openWorker.started.connect(lambda: self.loadingWindow(True))
            self.openWorker.finished.connect(lambda: self.loadingWindow(False))
        self.openWorker.start()

    def loadingWindow(self, popUp):
        if popUp:
            self.LoadDialog = Ui_LoadDialog()
            self.LoadDialog.exec_()
        else:
            self.LoadDialog.close()

    # --------
    # staistic
    # --------
    def ioFlowStats(self):
        """
            Input Output package statistic
            x axis --> second
            y axis --> Input / Output per second packets
        """

        # print(self.recvs)
        # print(self.sents)
        # print(self.timestamps)
        output, inputs, figureTitle = self.drawPrepare(self.sents, self.recvs,
                                                       self.timestamps)
        self.drawing(inputs, output, 'Input/Output flow', 'Input', 'Output',
                     figureTitle, 'Second', 'Packages (packages/scecond)')
        # print(input, output, seconds)
        # print(self.sents, self.recvs)

    def speedStats(self):
        """
             upload/download speed statistic
            x axis --> second
            y axis --> upload / download per second packets
        """
        figureTitle = self._subTitle(self.timestamps)
        self.drawing(self.uploads, self.downloads, 'Upload/Download Speed',
                     'Upload', 'Download', figureTitle, 'Second',
                     'kiloByte (KB/scecond)')

    def drawPrepare(self, data1, data2, ts):
        """ Draw plot figure prepare"""

        d1Diff = self._getDiff(data1)
        d2Diff = self._getDiff(data2)
        title = self._subTitle(ts)
        return d1Diff, d2Diff, title

    def _subTitle(self, ts):
        """Generate time format sub title """
        start = self._tsToDate(ts[0])
        end = self._tsToDate(ts[-1])
        subTitle = 'Input/Output packages traffice figure'
        title = '{} - {}\n{}'.format(start, end, subTitle)
        return title

    def _tsToDate(self, ts):
        """ Convert timestamp to readable date string """

        refineTS = int(str(ts).split('.')[0]) + self.CST_time_zone
        date = datetime.utcfromtimestamp(refineTS).strftime('%Y-%m-%d %H:%M:%S')
        return date

    @staticmethod
    def _getDiff(target):
        """ Return Diff list """

        diff = [target[i] - target[i - 1] if i != 0 else target[i] for i in
                range(len(target))]
        return diff

    def drawing(self, data1, data2, windowTitle, y1labl, y2label, figureTitle,
                xlabl, ylabel):
        seconds = np.arange(1, len(self.timestamps) + 1)
        self.ioFlow = Ui_StatisticDialog(subTitle=windowTitle)
        self.ioFlow.figure.clear()
        ax = self.ioFlow.figure.add_subplot(111)
        ax.set_title(figureTitle)
        ax.xaxis.set_major_locator(MaxNLocator(integer=True))
        ax.plot(seconds, data1, 'r-o', markersize=8, alpha=0.7, label=y1labl)
        ax.plot(seconds, data2, 'b-D', markersize=8, alpha=0.7, label=y2label)
        ax.set_xlabel(xlabl, alpha=0.8, fontweight='bold')
        ax.set_ylabel(ylabel, alpha=0.8, fontweight='bold')

        ax.set_xticks(seconds)
        # ax.set_yticks(range(max(input + output) + 3))
        ax.set_xlim(left=0)
        ax.set_ylim(bottom=-1)
        ax.grid(color='green', alpha=0.8)
        ax.legend(loc='best')
        self.ioFlow.canvas.draw()
        self.ioFlow.exec_()

    # -----------
    # scan method
    # -----------

    def scanLanNet(self, scanTarget):
        """
            * Make sure it's a ip address at least has a dot
            Reset the nodeListWidget current row avoid index out or range
            Store a nodesList data
            Scan thread work to scan Lan network
            Scan thread signal mapping
            When the scan parameter is wrong, emit tips message
        """

        if '.' in scanTarget:
            self.nodeListWidget.setCurrentRow(-1)
            self.nodeItems.clear()
            self.nodeListWidget.clear()
            localNode = self.node(self.ipAddr, self.macAddr, self.vendor,
                                  'local')
            self.nodeItems.append(localNode)

            self.scanWorker = ScanThread(self.inetName, scanTarget,
                                         self.macAddr,
                                         self.gwIpAddr, self.node,
                                         self.nodeItems,
                                         self.nicType)

            self.scanWorker.finishSignal[bool, str].connect(
                self.notifyRelatePanel)
            self.scanWorker.finishSignal[bool].connect(self.notifyRelatePanel)
            self.scanWorker.warnSignal.connect(self.XWarning)
            self.scanWorker.updateSignal.connect(self.scanNodesInsert)
            self.scanWorker.start()

    def notifyRelatePanel(self, finish, scanTarget=None):
        """
            Notify the scan panel/scan tab that the scan process is begin or finish
            Clear the listNode, append scan method name

            status --> False --> begin
            status --> True --> finish
                begin:
                    menu export LAN disable
                    clear the nodeList
                    protect button
                finish:
                    protect button
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

        if not done:
            self.action_Filter.setEnabled(False)
        else:
            if self.tcpdumpCheck:
                self.action_Filter.setEnabled(done)

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
            item.setText('{} ({})'.format(node.vendor[:14], node.ipAddr))
            nodeIcon = self._selectIco(node.sort)
            icoFile = '{}/{}'.format(BrightMainWindow.iconDir, nodeIcon)
            item.setIcon(QtGui.QIcon(icoFile))
            self.nodeListWidget.addItem(item)

        self.menuLAN_info.setEnabled(True)
        # print(self.nodeItems)

    def _selectIco(self, sort):
        """ Via node sort to select ico file"""

        if sort == 'local':
            icoFileName = 'local.ico'
        elif sort == 'gateway':
            icoFileName = 'gateway.ico'
        else:
            icoFileName = 'remote.ico'
        return icoFileName

    # ---------
    # query tab
    # ---------
    def queryIPInfo(self):
        """ Searh ip information(JSON format) and display it in the textEdit """

        self.sipTextEdit.clear()
        ip = self.sipLineEdit.text()

        self.queryWorker = QueryThread(ip)
        self.queryWorker.infoSignal.connect(self.queryInfo)
        self.queryWorker.finishSignal.connect(self.queryButton)
        self.queryWorker.jsonSignal.connect(self.queryDisplay)
        self.queryWorker.start()

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

    # -----------
    # Terms query
    # -----------
    def queryTerms(self):
        """ Query the terms get the result display to the textEdit """

        term = self.termLineEdit.text().strip()
        if term:
            self.termTextEdit.clear()
            self.termWorker = TermsThread(term)
            self.termWorker.infoSignal.connect(self.queryInfo)
            self.termWorker.finishSignal.connect(self.changeTermBtn)
            self.termWorker.htmlSignal.connect(self.termDisplay)
            self.termWorker.start()
        else:
            self.queryInfo('Query Info', 'Please input your terms first')

    def changeTermBtn(self, done):
        """
            done --> False --> lock button
            done --> true --> unlock button
        """

        self.termButton.setEnabled(done)

    def termDisplay(self, htmlStr):
        """ Display the html text in textEdit """

        self.termTextEdit.setText(htmlStr)

    # -------------
    # search button
    # -------------
    def searchProt(self):
        """
            Protocol search button click
                * search container initial
                * get search packages
                * display the package
         """

        self.searchPkts.clear()
        self.searchPkts = self._matchProt()
        self.conciseInfoTable.setRowCount(0)
        self.conciseInfoTable.clearContents()
        self._resetTabs()
        if self.searchPkts:
            self.searchWorker = SearchThread(self.searchPkts)
            self.searchWorker.scrollSignal.connect(
                self.conciseInfoTable.scrollToTop)
            self.searchWorker.searchSignal.connect(self.insertBriefPkt)
            if len(self.searchPkts) > 3000:
                self.searchWorker.started.connect(
                    lambda: self.loadingWindow(True))
                self.searchWorker.finished.connect(
                    lambda: self.loadingWindow(False))
            self.searchWorker.start()

    def _resetTabs(self):
        # concise tabs
        self.linkTextEdit.clear()
        self.linkTextEdit.setStyleSheet("")
        self.interTextEdit.clear()
        self.interTextEdit.setStyleSheet("")
        self.transTextEdit.clear()
        self.transTextEdit.setStyleSheet("")
        self.appTextEdit.clear()
        self.appTextEdit.setStyleSheet("")

        # verbose tabs
        self.utfTextEdit.clear()
        self.utfTextEdit.setStyleSheet("")
        self.rawTextEdit.clear()
        self.rawTextEdit.setStyleSheet("")

    def _matchProt(self):
        """ Match the search protocol then return package """

        empty = ''
        prots = self.searchLineEdit.text()
        if prots is empty:
            return deepcopy(self.rarePkts)
        elif '.' in prots:
            searchResult = self._nestSearch(prots)
        elif ',' in prots:
            searchResult = self._multiSearch(prots)
        else:
            searchResult = self._singleSearch(prots)

        return searchResult

    def _singleSearch(self, prot):
        """ Single protocol search """

        pktColletc = []
        prot = prot.strip().lower()
        protSet = {prot}
        success = self._checkSearch(protSet)
        if success:
            for pkt in self.rarePkts:
                if prot in pkt.pktProtStack:
                    pktColletc.append(pkt)
            return pktColletc
        else:
            self._searchWarning()
            return []

    def _multiSearch(self, prots):
        """ Multi protocol search, separate protocol by a (,) """

        pktsCollect = []
        protSet = set([i.strip().lower() for i in prots.split(',')])

        success = self._checkSearch(protSet)
        if success:
            for pkt in self.rarePkts:
                # Ensure one of the protocol match stack
                confirm = protSet & set(pkt.pktProtStack)
                if confirm:
                    pktsCollect.append(pkt)
            return pktsCollect
        else:
            self._searchWarning()
            return []

    def _nestSearch(self, prots):
        """ Nest protocl search, protocol separate by a (.) """

        pktsCollect = []
        protSet = set([i.strip().lower() for i in prots.split('.')])

        success = self._checkSearch(protSet)
        if success:
            for pkt in self.rarePkts:
                # Ensure every protocol match the stack
                if protSet & set(pkt.pktProtStack) == protSet:
                    pktsCollect.append(pkt)
            return pktsCollect
        else:
            self._searchWarning()
            return []

    def _checkSearch(self, prot):
        """ Check the search world whether under the search protocol """

        matchProt = RoughPacket.supportPort
        if prot & matchProt == prot:
            return True
        return False

    def _searchWarning(self):
        """ Search warning display the protol and tips """

        matchProt = RoughPacket.supportPort
        title = 'Search warning'
        matchProt = sorted(matchProt)
        support = str(matchProt).replace("'", '').strip('[').strip(
            ']')
        warning = "Make sure your seach protocol contain in below :\n" + support + '\n'
        theLine = '-' * 100 + '\n'
        commasTips = '(,) : Multi protocols should separated by commas.\n'
        periodTips = '(.) : Nest protocols should separated by period.\n'
        xTips = 'However, mark sure don\'t mix them together! \n'
        tips = warning + theLine + commasTips + periodTips + xTips + theLine
        self.XWarning(title, tips)

    # ----------------------
    # analysis button change
    # ----------------------
    def changAnalBtn(self):
        """ When nodeListWidget click change analysis button text """

        index = self.nodeListWidget.currentRow()
        itemAddr = self.nodeItems[index].ipAddr
        analBtnText = 'Analysis ({})'.format(itemAddr)
        self.analysisButton.setText(analBtnText)
        self.analysisButton.setEnabled(True)
        self.action_Start.setEnabled(True)

    def showNodeDialog(self):
        """ Display the node content information """

        index = self.nodeListWidget.currentRow()
        node = self.nodeItems[index]
        self.nodeDialog = Ui_NodeDialog()
        self.nodeDialog.nodeIpLineEdit.setText(node.ipAddr)
        self.nodeDialog.nodeMacLineEdit.setText(node.macAddr)
        self.nodeDialog.nodeVendorLineEdit.setText(node.vendor)
        self.nodeDialog.nodeTypeLineEdit.setText(node.sort)
        self.nodeDialog.exec_()

    # ---------------
    # analysis button
    # ---------------
    def analysisManage(self):
        """
            Manage the analysis process
            * widget control manage
            * Filter manage
                * filter protocol select
                * generate filter macro
            * Network Traffic manage
                * upload speed
                * download speed
            * Packet filter start
                * startup socket
                * apply filter macro to socket
                * capture packets and timestamps
            * Display info to conciseTable
        """
        title = 'Analysis warn!'

        routingTips = '''Tips:\n
* Make sure you already open ip-routing.\n
    open ip routing: https://bit.ly/2ERZw9P
'''

        filterTips = '''Tips:\n
* Make sure your scan target is a host not a gateway.
* Make sure your filter string qualify BPF syntax.\n
    BPF syntax: https://bit.ly/2dgiQha \n
'''
        nodeIndex = self.nodeListWidget.currentRow()
        nodeInfo = self.nodeItems[nodeIndex]

        filterMacros = self.analClkFilterMacro(nodeInfo)
        if filterMacros:
            Done = self.analClkCapture(nodeInfo, filterMacros)
            if Done:
                self.analClkWidgetChange()
                self.analClkNetworkTraffic()
            else:
                self.stopClkWidgetChange()
                return self.XWarning(title, routingTips)
        else:
            self.stopClkWidgetChange()
            return self.XWarning(title, filterTips)

    # def _analysisWarn(self, tips, title='Analysis warn!'):
    #     self.stopClkWidgetChange()
    #     QtWidgets.QMessageBox.warning(self, title, tips)

    def analClkWidgetChange(self):
        """
            Analysis button click widget change
                * reinitial the rare package container
                * menu status manage
                * control panel manage
                * scan panel manage
                * conciseTable, verboseTabs, decodeTabs manage
                * concise table menu
        """

        # packet container
        self.rarePkts.clear()
        self.searchPkts.clear()
        self.timestamps.clear()
        self.uploads.clear()
        self.downloads.clear()
        self.sents.clear()
        self.recvs.clear()
        # Menu
        self.action_Save.setEnabled(False)
        self.action_Open.setEnabled(False)
        self.action_Start.setEnabled(False)
        self.action_Stop.setEnabled(True)
        self.action_Restart.setEnabled(True)
        self.menuPackets_info.setEnabled(False)
        self.menu_Statistic.setEnabled(False)
        self.action_Filter.setEnabled(False)
        self.action_RefreshRank.setEnabled(False)

        # Control Panel
        self.rangeLineEdit.setEnabled(False)
        self.refreshButton.setEnabled(False)
        self.rangeButton.setEnabled(False)
        self.maskLineEdit.setEnabled(False)
        self.maskButton.setEnabled(False)
        self.searchLineEdit.setEnabled(True)
        self.searchButton.setEnabled(False)

        # Scan Paenl
        self.nodeListWidget.setEnabled(False)
        value = 0
        self.scanProgressBar.setMaximum(value)
        self.scanProgressBar.setMinimum(value)
        self.scanProgressBar.setValue(value)
        self.stopButton.setEnabled(True)
        self.analysisButton.setEnabled(False)

        # ConciseTable, verboseTabs, decodeTabs
        self.conciseInfoTable.setRowCount(0)
        self.conciseInfoTable.clearContents()
        self.conciseInfoTable.setEnabled(True)
        self.linkTextEdit.clear()
        self.linkTextEdit.setReadOnly(True)
        self.linkTab.setEnabled(True)

        self.interTextEdit.clear()
        self.interTextEdit.setReadOnly(True)
        self.interTab.setEnabled(True)

        self.transTextEdit.clear()
        self.transTextEdit.setReadOnly(True)
        self.transTab.setEnabled(True)

        self.appTextEdit.clear()
        self.appTextEdit.setReadOnly(True)
        self.appTab.setEnabled(True)
        self.verboseInfoTab.setEnabled(True)

        self.rawTextEdit.clear()
        self.rawTextEdit.setReadOnly(True)
        self.rawTab.setEnabled(True)

        self.utfTextEdit.clear()
        self.utfTextEdit.setReadOnly(True)
        self.utfTab.setEnabled(True)
        self.decodeInfoTab.setEnabled(True)
        self._resetTabs()

        # table menu
        self.showTableMenu()

    def showTableMenu(self):
        self.conciseInfoTable.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.conciseInfoTable.customContextMenuRequested.connect(
            self.queryMenuShow)

        self.queryMenu = QtWidgets.QMenu()
        sourceFile = '{}/{}'.format(ShineMainWindow.iconDir, 'source.ico')
        sourceIcon = QtGui.QIcon(sourceFile)
        querySrc = self.queryMenu.addAction('Query source')
        querySrc.setIcon(sourceIcon)

        destinationFile = '{}/{}'.format(ShineMainWindow.iconDir,
                                         'destination.ico')
        destinationIcon = QtGui.QIcon(destinationFile)
        queryDst = self.queryMenu.addAction('Query destination')
        queryDst.setIcon(destinationIcon)

        protocolFile = '{}/{}'.format(ShineMainWindow.iconDir, 'protocol.ico')
        protocolIcon = QtGui.QIcon(protocolFile)
        queryProt = self.queryMenu.addAction('Query protocol')
        queryProt.setIcon(protocolIcon)

        querySrc.triggered.connect(lambda: self._menuQueryAddr(2))
        queryDst.triggered.connect(lambda: self._menuQueryAddr(3))
        queryProt.triggered.connect(self._menuQueryProt)

    def queryMenuShow(self, pos):
        """ Display the query menu """

        self.queryMenu.move(self.pos() + pos)
        self.queryMenu.show()

    def _menuQueryAddr(self, addrPos):
        """ Concise table right click query address """

        sipTabIndex = 3
        try:
            addr = self.conciseInfoTable.item(
                self.conciseInfoTable.currentRow(), addrPos).text()
        except AttributeError:
            pass
        else:
            #  Make sure it is IPv4 address
            if '.' in addr:
                self.controlDock.setVisible(True)
                self.controlTabManage.setCurrentIndex(sipTabIndex)
                self.sipLineEdit.setText(addr)
                self.sipButton.click()
            else:
                title = 'Address Query Warning'
                tips = 'Make sure your query object is IP(eg: 8.8.8.8) address)'
                self.XWarning(title, tips)

    def _menuQueryProt(self):
        """ Concise table right crlick query terms """

        termIndex = 4
        protField = 4
        try:
            term = self.conciseInfoTable.item(
                self.conciseInfoTable.currentRow(), protField).text()
        except AttributeError:
            pass
        else:
            self.controlDock.setVisible(True)
            self.controlTabManage.setCurrentIndex(termIndex)
            self.termLineEdit.setText(term)
            self.termButton.click()

    def analClkFilterMacro(self, nodeInfo):
        """
            According to filterDict and node type
            generate filter macro
                * gateway --> None
                * remote/host
                    * append mac address filter string
                * remote --> append `not arp` filter string
                * host -->  if filter string not empty add `(` `)` in filter
        """

        decorateFltrStr = ''
        originalFltStr = ''
        withAnd = ''

        isRemote = True if nodeInfo.sort == 'remote' else False
        isNotEmpty = True if len(self.filterDict['filter']) > 0 else False

        # Refuse gateway
        if nodeInfo.sort != 'gateway':
            # All host append decorate filter sring
            broadcast = 'ff:ff:ff:ff:ff:ff'
            decorateFltrStr = '(ether host {} or ether dst host {} or ether dst host {}) '.format(
                nodeInfo.macAddr, nodeInfo.macAddr, broadcast)

            # Remote host need to append `not arp`
            if isRemote:
                decorateFltrStr = ' (not arp) and ' + decorateFltrStr

            # Original filter string `add bracket`  `assign withAnd`
            if isNotEmpty:
                originalFltStr = '(' + self.filterDict['filter'] + ')'
                withAnd = ' and '

            # combine filterSting
            filterString = "'{} {} {}'".format(decorateFltrStr, withAnd,
                                               originalFltStr)

            # print(filterString)
            if self.inetNameAlias:
                deviceName = self.inetNameAlias
            else:
                deviceName = self.inetName
            cmd = "sudo tcpdump -s 0 -i {interface} -dd {filters}".format(
                interface=deviceName, filters=filterString)
            try:
                tcpdumpBinary = subprocess.check_output(cmd, shell=True)
            except subprocess.CalledProcessError:
                pass
            else:
                macros = self._generateMacro(tcpdumpBinary)
                # print(macros)
                return macros
        return None

    @staticmethod
    def _generateMacro(tcpdumpBinary):
        """
            Generate the macro
            tcpdumpBinary -->
                b'{ 0x28, 0, 0, 0x0000000c },\n{ 0x15, 0, 3, 0x000008...
                * decode the string to utf-8
                * replace '\n'
                * adding variable name `macroString`
                * replace {} to [] (because set just keep different element)
                * execute the macroString
        """

        macroString = '( ' + tcpdumpBinary.decode('utf-8').replace(
            '\n', '').replace('{', '[').replace('}', ']') + ')'

        # https://stackoverflow.com/questions/2220699/whats-the-difference-between-eval-exec-and-compile
        macroString = eval(macroString)
        return macroString

    def analClkCapture(self, nodeInfo, filterMacros):
        """
            Analysis button click capute the package
                * Remote node star arp poison
                * set the filterMarco to sockets
        """

        if nodeInfo.sort == 'remote':
            if self.ipRoutingCheck():
                self._arpPoisonTarget(nodeInfo.macAddr, nodeInfo.ipAddr)
            else:
                return False

        self._captureStart(self.inetName, filterMacros)
        return True

    def _arpPoisonTarget(self, targetMac, targetIp):
        """ Posion the target via arp flow """

        # PoiosnThread(localMac, deceiveIp, sendToMac, sendToIp)
        self.targetPoison = PoisonThread(self.macAddr, self.gwIpAddr,
                                         targetMac, targetIp)
        self.gatewayPoison = PoisonThread(self.macAddr, targetIp,
                                          self.gwMacAddr, self.gwIpAddr)
        self.poisonWorkers = [self.targetPoison, self.gatewayPoison]

        for worker in self.poisonWorkers:
            worker.start()

    def _captureStart(self, inetName, macros):
        """ Start the capture thread """

        self.captureWorker = CaptureThread(inetName, macros)
        self.captureWorker.packetSignal.connect(self.unpackPacket)
        self.captureWorker.start()

    def unpackPacket(self, tsSec, tsUsec, index, packet):
        """ Unpack the packet to generate a brief packet inform and insert it """

        briefPkt = RoughPacket(tsSec, tsUsec, index, packet)
        # print(briefPkt)
        self.rarePkts.append(briefPkt)
        self.insertBriefPkt(briefPkt)
        # self.processPackets.append(packet)

    def insertBriefPkt(self, briefPkt):
        """ In sert brief packet info to the concise table """

        # Insert info prepare
        pktDatas = briefPkt.getBriefPacket()
        pktColor = briefPkt.getColor()
        # Append a  blank row
        self.conciseInfoTable.insertRow(self.conciseInfoTable.rowCount())
        pktRow = self.conciseInfoTable.rowCount() - 1

        # Insert data to the row
        for pktCol, data in enumerate(pktDatas):
            pktItem = QtWidgets.QTableWidgetItem(str(data))
            pktItem.setBackground(pktColor)
            if pktCol < 6:
                pktItem.setTextAlignment(QtCore.Qt.AlignCenter)
            self.conciseInfoTable.setItem(pktRow, pktCol, pktItem)
        self.conciseInfoTable.scrollToBottom()

    def analClkNetworkTraffic(self):
        """ Network traffic display """

        self.timestamps.clear()
        self.uploads.clear()
        self.downloads.clear()
        self.sents.clear()
        self.recvs.clear()

        self.trafficWorker = TrafficThread(self.inetName)
        self.trafficWorker.trafficSignal.connect(self.trafficProcess)
        self.trafficWorker.start()

    def trafficProcess(self, timestamp, upload, download, sent, recv):
        """ Handle the traffic data display and record  """

        upload = round(upload, 3)
        download = round(download, 3)
        self.uploadLabel.setText('upload: {:02} KB |'.format(upload))
        self.downloadLabel.setText('download: {:02} KB |'.format(download))
        self.packageSentLabel.setText('sent: {} packages |'.format(sent))
        self.packageRecveLabel.setText('receive: {} packages'.format(recv))

        self.timestamps.append(timestamp)
        self.uploads.append(upload)
        self.downloads.append(download)

        self.sents.append(sent)
        self.recvs.append(recv)

    # -----------
    # stop button
    # -----------
    def stopManage(self):
        """
            Manage stop caputre process
            * Network Traffic stop
            * widget control manage
        """

        # Stop poison workers
        try:
            for worker in self.poisonWorkers:
                worker.stop()
        except AttributeError:
            pass
        # Stop capture worker
        try:
            self.captureWorker.stop()
            self.captureWorker.packetSignal.disconnect(self.unpackPacket)
        except AttributeError:
            pass
        # Stop traffic worker
        try:
            self.trafficWorker.stop()
        except AttributeError:
            pass

        try:
            self.parseWorker.stop()
        except AttributeError:
            pass

        # Widget control manage
        self.stopClkWidgetChange()

    def stopClkWidgetChange(self):
        """
            Stop button click widget change
                * menu status manage
                * control panel manage
                * scan panel manage
                * conciseTable, verboseTabs, decodeTabs manage
        """

        # Menu
        if self.rarePkts:
            self.action_Save.setEnabled(True)
            self.menuPackets_info.setEnabled(True)
            self.menu_Statistic.setEnabled(True)
            self.menu_protocol.setEnabled(True)
            self.menu_flow.setEnabled(True)
            self.menu_length.setEnabled(True)
        self.action_Open.setEnabled(True)
        self.action_Start.setEnabled(True)
        self.action_Stop.setEnabled(False)
        self.action_Restart.setEnabled(False)
        self.action_Filter.setEnabled(True)
        self.action_RefreshRank.setEnabled(True)

        # Control Panel
        self.refreshButton.setEnabled(True)
        self.rangeLineEdit.setEnabled(True)
        self.rangeButton.setEnabled(True)
        self.maskLineEdit.setEnabled(True)
        self.maskButton.setEnabled(True)
        self.searchButton.setEnabled(True)

        # Scan Panel
        self.nodeListWidget.setEnabled(True)
        value = 100
        self.scanProgressBar.setMaximum(value)
        self.scanProgressBar.setMinimum(value)
        self.scanProgressBar.setValue(value)
        self.analysisButton.setEnabled(True)
        self.stopButton.setEnabled(False)

        # conciseTable, verboseTabs, decodeTabs manage
        # self._resetTabs()

        # Status bar
        self.clearStatusBarText()

    # -------------
    # filter dialog
    # -------------
    def settingFilterDict(self):
        """
            Menubar --> Option --> &filter
            show filter dialog information
        """

        self.filterDialog = ui_FilterDialog(self.filterDict)
        self.filterDialog.filterSignal.connect(self.filterStatusBar)
        self.filterDialog.exec_()

    def filterStatusBar(self, reciveDict):
        """" Assign the filterDict, notify status bar """

        self.filterDict = reciveDict
        filterText = 'filter'
        filterStrDecode = self.filterDict['filter'].replace('||', ' or ')
        filterStrDecode = filterStrDecode.replace('&&', ' and ')

        if filterStrDecode:
            if len(filterStrDecode) > 30:
                filterStrDecode = filterStrDecode[:30] + '...'
            self.filterLabel.setText('{}: {}'.format(filterText,
                                                     filterStrDecode))
        else:
            self.filterLabel.setText('{}: {}'.format(filterText, 'disable'))

    # --------------
    # restart action
    # --------------
    def stopStart(self):
        self.stopButton.click()
        sleep(0.5)
        self.analysisButton.click()

    # ------------
    # Parse packet
    # ------------
    def parsePacket(self, currentRow):
        """
            Parse the packet
                * Get current packet color to set background
                * Get the packet protocol stack to parse
                * display the info to tabs
        """

        noPosit = 0
        try:
            index = self.conciseInfoTable.item(currentRow, noPosit).text()
        except AttributeError:
            pass
        else:
            index = int(index) - 1
            packet = self.rarePkts[index]
            color = packet.getColor().getRgb()

            self.parseWorker = ParseThread(packet)
            self.parseWorker.started.connect(lambda: self._followStyle(color))
            self.parseWorker.cookedSignal.connect(self.displayParse)
            self.parseWorker.start()

    def displayParse(self, cookedPkt):
        """ Display the parse info to verbose tabs and decode tabs """

        self.linkTextEdit.setPlainText(cookedPkt.linkLayer)
        self.interTextEdit.setPlainText(cookedPkt.interLayer)
        self.transTextEdit.setPlainText(cookedPkt.transLayer)
        self.appTextEdit.setPlainText(cookedPkt.appLayer)

        self.rawTextEdit.setPlainText(cookedPkt.rawDecode)
        self.utfTextEdit.setPlainText(cookedPkt.utfDecode)

    def _followStyle(self, bgColor):
        """ Follow the packet color set the verbose tabs and decode tabs style """

        font = 'DejaVu Sans Mono, consolas'
        fontColor = 'black'
        fontSize = '14px'
        tabsStyle = """background-color: rgba{}; 
                           color: {}; 
                           font-size: {};
                           font-family: {};
                           """.format(bgColor, fontColor, fontSize, font)

        self.linkTextEdit.setStyleSheet(tabsStyle)
        self.interTextEdit.setStyleSheet(tabsStyle)
        self.transTextEdit.setStyleSheet(tabsStyle)
        self.appTextEdit.setStyleSheet(tabsStyle)
        self.rawTextEdit.setStyleSheet(tabsStyle)
        self.utfTextEdit.setStyleSheet(tabsStyle)
