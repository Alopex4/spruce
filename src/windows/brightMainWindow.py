#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
import json
import subprocess
from functools import namedtuple

import netifaces
from PyQt5 import QtGui
from PyQt5 import QtWidgets

from capturePkt.roughPacket import RoughPacket
from threads.queryThread import QueryThread
from threads.scanThread import ScanThread
from threads.trafficThread import TrafficThread
from threads.poisonThread import PoisonThread
from threads.captureThread import CaptureThread
from dialogs.shineDialog import ui_FilterDialog
from dialogs.shineDialog import Ui_NodeDialog
from windows.shineMainWindow import ShineMainWindow


class BrightMainWindow(ShineMainWindow):
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
        self.briefPkts = []

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
        self.action_Start.triggered.connect(self.analysisButton.click)
        self.action_Stop.triggered.connect(self.stopButton.click)
        self.action_Filter.triggered.connect(self.settingFilterDict)

        # Config panel button mapping
        self.refreshButton.clicked.connect(self.refreshBtnClick)
        self.rangeButton.clicked.connect(
            lambda: self.scanLanNet(self.rangeLineEdit.text()))
        self.maskButton.clicked.connect(
            lambda: self.scanLanNet(self.maskLineEdit.text()))
        self.sipButton.clicked.connect(self.queryIPInfo)

        # Scan panel button mapping
        self.nodeListWidget.itemSelectionChanged.connect(self.changAnalBtn)
        self.nodeListWidget.itemDoubleClicked.connect(self.showNodeDialog)
        self.analysisButton.clicked.connect(self.analysisManage)
        self.stopButton.clicked.connect(self.stopManage)

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
        """ Get wired network interface name (include 'en') """

        for netName in netifaces.interfaces():
            if 'en' in netName:
                return netName

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
            self.gwMacAddr = '`pppoe` link no gateway mac'
            self.gwVendor = '`pppoe` link no gateway vendor'

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

    def scanLanNet(self, scanTarget):
        """ 
            Reset the nodeListWidget current row avoid index out or range
            Store a nodesList data
            Scan thread work to scan Lan network
            Scan thread signal mapping
            When the scan parameter is wrong, emit tips message
        """

        self.nodeListWidget.setCurrentRow(-1)
        self.nodeItems.clear()
        self.nodeListWidget.clear()
        localNode = self.node(self.ipAddr, self.macAddr, self.vendor, 'local')
        self.nodeItems.append(localNode)

        self.scanWorker = ScanThread(self.inetName, scanTarget, self.macAddr,
                                     self.gwIpAddr, self.node, self.nodeItems,
                                     self.nicType)

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
            parentDir = '../icon/'
            icoFile = '{}/{}'.format(parentDir, nodeIcon)
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

        nodeIndex = self.nodeListWidget.currentRow()
        nodeInfo = self.nodeItems[nodeIndex]

        self.analClkWidgetChange()
        filterMacros = self.analClkFilterMacro(nodeInfo)
        if filterMacros:
            Done = self.analClkCapture(nodeInfo, filterMacros)
            if Done:
                self.analClkNetworkTraffic()
            else:
                routingTips = '''Tips:\n
* Make sure you already open ip-routing.\n
    open ip routing: https://bit.ly/2ERZw9P
'''
                self._analysisWarn(routingTips)

        else:
            filterTips = '''Tips:\n
* Make sure your scan target is a host not a gateway.
* Make sure your filter string qualify BPF syntax.\n
    BPF syntax: https://bit.ly/2dgiQha \n
'''
            self._analysisWarn(filterTips)

    def _analysisWarn(self, tips, title='Analysis warn!'):
        self.stopClkWidgetChange()
        QtWidgets.QMessageBox.warning(self, title, tips)

    def analClkWidgetChange(self):
        """
            Analysis button click widget change
                * menu status manage
                * control panel manage
                * scan panel manage
                * conciseTable, verboseTabs, decodeTabs manage
        """

        # Menu
        self.action_Save.setEnabled(True)

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
        self.searchButton.setEnabled(True)

        # Scan Paenl
        self.nodeListWidget.setEnabled(False)
        value = 0
        self.scanProgressBar.setMaximum(value)
        self.scanProgressBar.setMinimum(value)
        self.scanProgressBar.setValue(value)
        self.stopButton.setEnabled(True)
        self.analysisButton.setEnabled(False)

        # ConciseTable, verboseTabs, decodeTabs
        self.conciseInfoTable.clearContents()
        self.conciseInfoTable.setEnabled(True)
        self.linkTextEdit.clear()
        self.linkTextEdit.setReadOnly(True)
        self.linkTab.setEnabled(True)

        self.interTextEdit.clear()
        self.interTextEdit.setReadOnly(True)
        self.interTab.setEnabled(True)

        self.TransTextEdit.clear()
        self.TransTextEdit.setReadOnly(True)
        self.transTab.setEnabled(True)

        self.appTextEdit.clear()
        self.appTextEdit.setReadOnly(True)
        self.appTab.setEnabled(True)
        self.verboseInfoTab.setEnabled(True)

        self.rawTextEdit.clear()
        self.rawTextEdit.setReadOnly(True)
        self.rawTab.setEnabled(True)

        self.hexTextEdit.clear()
        self.hexTextEdit.setReadOnly(True)
        self.hexTab.setEnabled(True)
        self.decodeInfoTab.setEnabled(True)

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
                macros = BrightMainWindow._generateMacro(tcpdumpBinary)
                print(macros)
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

        print(nodeInfo)
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
        """ Unpack the packet to generate a brief packet inform """

        briefPkt = RoughPacket(tsSec, tsUsec, index, packet)
        print(briefPkt)
        self.briefPkts.append(briefPkt)

        # packet = CookedPacket(threading.Lock())
        # self.processPackets.append(packet)

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
        self.action_Save.setEnabled(True)
        self.action_Open.setEnabled(True)
        self.menuPackets_info.setEnabled(True)
        self.action_Start.setEnabled(True)
        self.action_Stop.setEnabled(False)
        self.action_Restart.setEnabled(False)
        self.menu_Statistic.setEnabled(True)
        self.menu_protocol.setEnabled(True)
        self.menu_time.setEnabled(True)
        self.menu_length.setEnabled(True)
        self.action_Filter.setEnabled(True)
        self.action_RefreshRank.setEnabled(True)

        # Control Panel
        self.refreshButton.setEnabled(True)
        self.rangeLineEdit.setEnabled(True)
        self.rangeButton.setEnabled(True)
        self.maskLineEdit.setEnabled(True)
        self.maskButton.setEnabled(True)

        # Scan Panel
        self.nodeListWidget.setEnabled(True)
        value = 100
        self.scanProgressBar.setMaximum(value)
        self.scanProgressBar.setMinimum(value)
        self.scanProgressBar.setValue(value)
        self.analysisButton.setEnabled(True)
        self.stopButton.setEnabled(False)

        # conciseTable, verboseTabs, decodeTabs manage
        pass

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
