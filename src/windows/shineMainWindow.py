#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

import requests
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5 import QtWidgets

from windows.mainWindow import Ui_MainWindow
from dialogs.shineDialog import Ui_RankDialog
from dialogs.shineDialog import Ui_AuthorDialog

ROOT = 1
NETWORK = 2
ROUTING = 4
TCPDUMP = 8


class ShineMainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    # IP regular express
    ipRegex = ("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
               "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    # Range scan regular express
    rangeRegex = ("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    # Mask scan regular express
    maskRegex = (
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
        "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])/([1-9]|[1-2][0-9]|3[0-2])$"
    )

    def __init__(self, parent=None):
        super(QtWidgets.QMainWindow, self).__init__(parent)
        self.setupUi(self)
        self.shineUI()

    def shineUI(self):
        """ Make the UI looks more beauty and initial the UI status """

        self.shineBegin()
        self.shineDock()
        self.shineProgressBar()
        self.shineTable()
        self.shineStatusBar()
        self.shineInitUI()

    def shineBegin(self):
        """ 1. Set a prefect size (golden ration)
            2. Set a window title
            3. Set an icon
            4. Adjust window in central of the screen
        """

        # Task 1
        self.resize(1000, 618)
        # Task 2
        self.setWindowTitle('spruce -- a mix network analysis tool')
        # Task 3
        spruceIcon = '{}/{}'.format('../icon', 'spruce.ico')
        self.setWindowIcon(QtGui.QIcon(spruceIcon))
        # Task 4
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) / 2,
                  (screen.height() - size.height()) / 2)

    def shineDock(self):
        """ Set dock widget movable and floatable """

        self.controlDock.setFeatures(
            QtWidgets.QDockWidget.DockWidgetMovable
            | QtWidgets.QDockWidget.DockWidgetFloatable)

        self.scanDock.setFeatures(QtWidgets.QDockWidget.DockWidgetMovable
                                  | QtWidgets.QDockWidget.DockWidgetFloatable)

    def shineProgressBar(self):
        """ Set process bar look much better """

        self.scanProgressBar.setMinimum(100)
        self.scanProgressBar.setMaximum(100)
        self.scanProgressBar.setValue(0)
        # self.scanProgressBar.setProperty("value", 0)
        self.scanProgressBar.setTextVisible(False)

    def shineTable(self):
        """ Set concise infomation table look much better """

        self.conciseInfoTable.setShowGrid(False)
        self.conciseInfoTable.verticalHeader().setVisible(False)
        # Refuse to edit the the table
        self.conciseInfoTable.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        # Selet total line as an unit
        self.conciseInfoTable.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.conciseInfoTable.horizontalHeader().setStretchLastSection(True)

        # Testing code
        # self.conciseInfoTable.setRowCount(4)
        # item = QtWidgets.QTableWidgetItem('hello google')
        # self.conciseInfoTable.setItem(0, 0, item)

    def shineStatusBar(self):
        """ Set a label widget the monitor the download/upload status"""

        self.statusBar = QtWidgets.QStatusBar(self)
        self.statusBar.setFixedHeight(35)
        parentDir = '../icon/'
        filterFile = '{}/{}'.format(parentDir, 'filter.ico')
        filterIco = QtGui.QPixmap(filterFile)
        uploadFile = '{}/{}'.format(parentDir, 'upload.ico')
        uploadIco = QtGui.QPixmap(uploadFile)
        downloadFile = '{}/{}'.format(parentDir, 'download.ico')
        downloadIco = QtGui.QPixmap(downloadFile)
        packageSentFile = '{}/{}'.format(parentDir, 'packageSent.ico')
        packageSentIco = QtGui.QPixmap(packageSentFile)
        packageRecvFile = '{}/{}'.format(parentDir, 'packageRecv.ico')
        packageRecvIco = QtGui.QPixmap(packageRecvFile)

        self.filterLabel = QtWidgets.QLabel('filter: disable')
        self.filterIcoLabel = QtWidgets.QLabel('')
        self.filterIcoLabel.setPixmap(filterIco)

        self.uploadLabel = QtWidgets.QLabel('upload:  KB |')
        self.uploadIcoLabel = QtWidgets.QLabel('')
        self.uploadIcoLabel.setPixmap(uploadIco)

        self.downloadLabel = QtWidgets.QLabel('download:  KB |')
        self.downloadIcoLabel = QtWidgets.QLabel('')
        self.downloadIcoLabel.setPixmap(downloadIco)

        self.packageSentLabel = QtWidgets.QLabel('sent: packages |')
        self.packageSentIcoLabel = QtWidgets.QLabel('')
        self.packageSentIcoLabel.setPixmap(packageSentIco)

        self.packageRecveLabel = QtWidgets.QLabel('receive: packages')
        self.packageRecveIcoLabel = QtWidgets.QLabel('receive: packages')
        self.packageRecveIcoLabel.setPixmap(packageRecvIco)

        self.statusBar.addWidget(self.filterIcoLabel)
        self.statusBar.addWidget(self.filterLabel)
        self.statusBar.addPermanentWidget(self.uploadIcoLabel)
        self.statusBar.addPermanentWidget(self.uploadLabel)
        self.statusBar.addPermanentWidget(self.downloadIcoLabel)
        self.statusBar.addPermanentWidget(self.downloadLabel)
        self.statusBar.addPermanentWidget(self.packageSentIcoLabel)
        self.statusBar.addPermanentWidget(self.packageSentLabel)
        self.statusBar.addPermanentWidget(self.packageRecveIcoLabel)
        self.statusBar.addPermanentWidget(self.packageRecveLabel)
        self.setStatusBar(self.statusBar)

    def shineInitUI(self):
        """ Initial all the widget status
            1. define the rank
            2. action trigger connect
            3. widget status initial
        """

        # Task 1
        self.rank = self.getRank()
        # Task 2
        self.triggerInit()
        # Task 3
        self.allWidgetInit()

    # ---------------
    # define the rank
    # ---------------
    def getRank(self):
        """ 
            Manage the rank info 
                * root privilege  --> without affect --> application error      --> value 0000 0001
                * network startup --> without affect --> without ipinfo search  --> value 0000 0010
                * ip routing      --> without affect --> without remote sniffer --> value 0000 0100
                * tcpdump install --> without affect --> without filter feature --> value 0000 1000
        """

        rootPrivilege = self.rootPrivilegeCheck()
        networkStartUp = self.networkStartUpCheck()
        ipRouting = self.ipRoutingCheck()
        tcpdumpState = self.tcpdumpCheck()
        rank = rootPrivilege | networkStartUp | ipRouting | tcpdumpState
        return rank

    def rootPrivilegeCheck(self):
        """ Return 1 if effect user id equal 0 else return 0 """

        return 1 if os.getegid() == 0 else 0

    def networkStartUpCheck(self):
        """ Return 2 if network is startup else return 0 """

        test_web = 'http://ipinfo.io/ip'
        timeout = 0.5
        try:
            page = requests.get(test_web, timeout=timeout)
            return 2
        except (requests.ConnectionError, requests.ConnectTimeout,
                requests.ReadTimeout):
            return 0

    def ipRoutingCheck(self):
        """ Return 4 if ip routing is open else return 0"""

        cmd = 'cat /proc/sys/net/ipv4/ip_forward'.split()
        r = subprocess.run(cmd, stdout=subprocess.PIPE)
        done = int(r.stdout.decode('utf-8').strip('\n'))
        if done:
            return 4
        else:
            return 0

    def tcpdumpCheck(self):
        """ Return 8 if tcpdump is install else return 0 """

        cmd = 'tcpdump -h 2> /dev/null'
        return 8 if os.system(cmd) == 0 else 0

    # ----------------
    # Action triggered
    # ----------------
    def triggerInit(self):
        """ menu acion trigger initial """

        self.action_close.triggered.connect(self.close)
        self.action_Rank.triggered.connect(self.showRankDialog)
        self.action_Save.triggered.connect(self.showSaveFile)
        self.action_Open.triggered.connect(self.showOpenFile)
        self.action_Author.triggered.connect(self.showAuthorDialog)
        self.action_RefreshRank.triggered.connect(self.refreshRank)

    def showRankDialog(self):
        """ 
            Menubar --> About --> &rank 
            show root, network, routing, tcpdump all right or not
        """

        self.rank = self.getRank()
        rankDialog = Ui_RankDialog(self)

        parentDir = '../icon/'
        trueFile = '{}/{}'.format(parentDir, 'true.ico')
        trueIco = QtGui.QPixmap(trueFile)
        falseFile = '{}/{}'.format(parentDir, 'false.ico')
        falseIco = QtGui.QPixmap(falseFile)

        # Use `and` operator to get current active level
        stateIconList = [
            trueIco if self.rank & i == i else falseIco
            for i in [ROOT, NETWORK, ROUTING, TCPDUMP]
        ]
        # Store all the rankDialog label widget
        stateLabelList = [
            rankDialog.rootStateLabel, rankDialog.netStateLabel,
            rankDialog.routingStateLabel, rankDialog.dumpStateLabel
        ]

        # label --> label widget
        # icon --> pixmap object
        for label, icon in zip(stateLabelList, stateIconList):
            label.setPixmap(icon)

        rankDialog.exec_()

    def showSaveFile(self, fileName=None):
        """
            Menubar --> File --> &save
            Save a file in disk, auto append --> .pcap
        """

        if not fileName:
            # _ --> file types
            saveFileName, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, 'save file', '.', "pcaket files (*.pcap)")
            if '.pcap' not in saveFileName:
                saveFileName = saveFileName + '.pcap'
        else:
            saveFileName = fileName

    def showOpenFile(self):
        """
            Menubar --> File --> &open
            show open file dialog get open file name(.pcap)
        """

        # _ --> file types
        openFileName, _ = QtWidgets.QFileDialog.getOpenFileName(
            self, 'open file', '.', "packet files (*.pcap)")

    def showAuthorDialog(self):
        """
            Menubar --> About --> &author
            show author dialog information
        """

        auhtorDialog = Ui_AuthorDialog(self)
        auhtorDialog.exec_()

    # def showFilterDialog(self):
    #     """
    #         Menubar --> Option --> &filter
    #         show filter dialog information
    #         ROOT, NETWORK, tcpdump --> network tab, scan tab
    #     """

    #     if ((ROOT | NETWORK | TCPDUMP) & self.rank) == (ROOT | NETWORK
    #                                                     | TCPDUMP):
    #         self.filterDialog = ui_FilterDialog(self)
    #         self.filterDialog.exec_()
    #     else:
    #         tips = '''Check `about --> rank` more details.
    #             \nTips: Make sure you already install tcpdump!'''

    #         QtWidgets.QMessageBox.warning(self, 'filter warning', tips)

    def refreshRank(self):
        """
            Menubar --> Option --> &refresh rank
            1. refresh the rank
            2. clear all the text
        """

        self.rank = self.getRank()
        self.allWidgetInit()

    # --------------
    # widget initial
    # --------------
    def allWidgetInit(self):
        """ 
            Manage all the widget initial
                * menu action
                * control panel
                * scan panel
                * concise table
                * verbose tab
                * decode tabs
                * status bar
            clean all the text
        """

        # Menu initial
        self.menuInit()

        # control panel
        self.ctlPanelTabSwitch()
        self.ctlPanelContInit()

        # scanDock, conciseTable, verboseTabs, decoceTabs
        self.remainWidgetInit()

        # clean all text
        self.clearAllText()

        # status bar
        self.clearStatusBarText()

        # Obsolete object
        self.unlockButton.setVisible(False)

    def menuInit(self):
        """ Menu action initial """

        self.action_Save.setEnabled(False)
        self.menuNetwork_info.setEnabled(False)
        self.menu_export.setEnabled(False)
        self.menuLAN_info.setEnabled(False)
        self.menuPackets_info.setEnabled(False)
        self.action_Start.setEnabled(False)
        self.action_Stop.setEnabled(False)
        self.action_Restart.setEnabled(False)
        self.action_Filter.setEnabled(False)
        self.menu_time.setEnabled(False)
        self.menu_protocol.setEnabled(False)
        self.menu_length.setEnabled(False)

    def ctlPanelTabSwitch(self):
        """
            Control panel tab widget active/deactive, according to the rank level
            NETWORK --> search tab, ipinfo tab
            ROOT, NETWORK --> network tab, scan tab
        """

        if self.rank & NETWORK == NETWORK:
            self.searchTab.setEnabled(True)
            self.ipinfoTab.setEnabled(True)
        else:
            self.searchTab.setEnabled(False)
            self.ipinfoTab.setEnabled(False)

        if ((ROOT | NETWORK) & self.rank) == (ROOT | NETWORK):
            self.networkTab.setEnabled(True)
            self.scanTab.setEnabled(True)
        else:
            self.networkTab.setEnabled(False)
            self.scanTab.setEnabled(False)

    def ctlPanelContInit(self):
        """ 
            Control panel all contain widget need a initial status
            NetworkTab --> lock all lineEdit
            ScanTab --> paceholder and match pattern(range: 192.168.1.1-100, 
                mask: 192.168.1.0/24)
            SearchTab --> paceholder and tips
            ipinfo --> paceholder and tips 
        """

        # Network Tab
        self._netLineEditRO(True)

        # Scan Tab
        rangeRegexExp = QtCore.QRegExp(ShineMainWindow.rangeRegex)
        rangeValidator = QtGui.QRegExpValidator(rangeRegexExp,
                                                self.rangeLineEdit)
        self.rangeLineEdit.setValidator(rangeValidator)
        self.rangeLineEdit.setPlaceholderText('eg: 192.168.1-100')
        self.rangeLineEdit.setToolTip('Input Example: 192.168.1.1-100')
        self.rangeLineEdit.setStatusTip('Input Example: 192.168.1.1-100')
        self.rangeLineEdit.setAlignment(QtCore.Qt.AlignCenter)

        maskRegexExp = QtCore.QRegExp(ShineMainWindow.maskRegex)
        maskValidator = QtGui.QRegExpValidator(maskRegexExp, self.maskLineEdit)
        self.maskLineEdit.setValidator(maskValidator)
        self.maskLineEdit.setPlaceholderText('eg: 192.168.0/24')
        self.maskLineEdit.setToolTip('Input Example: 192.168.1.0/24')
        self.maskLineEdit.setStatusTip('Input Example: 192.168.1.0/24')
        self.maskLineEdit.setAlignment(QtCore.Qt.AlignCenter)

        # Search Tab
        self.searchLineEdit.setPlaceholderText('eg: http or https')
        self.searchLineEdit.setToolTip('search protocol')
        self.searchLineEdit.setStatusTip(
            'display the specific protocol after you start analysis')
        self.searchButton.setEnabled(False)

        # Info Tab
        ipRegexExp = QtCore.QRegExp(ShineMainWindow.ipRegex)
        ipValidator = QtGui.QRegExpValidator(ipRegexExp, self.sipLineEdit)
        self.sipLineEdit.setValidator(ipValidator)
        self.sipLineEdit.setPlaceholderText('eg: 8.8.8.8')
        self.sipLineEdit.setStatusTip(
            'Input an ip you want to query (defulat: query your public ip)')
        self.sipLineEdit.setToolTip('Input Example: 8.8.8.8')

        demoText = """{
    "ip": "8.8.8.8",
    "hostname": "google-public-dns-a.google.com",
    "city": "Mountain View",
    "region": "California",
    "country": "US",
    "loc": "37.3860,-122.0840",
    "postal": "94035",
    "phone": "650",
    "org": "AS15169 Google LLC"
}
        """
        self.sipTextEdit.setPlaceholderText(demoText)
        self.sipTextEdit.setReadOnly(True)

    def _netLineEditRO(self, state=False):
        """ Control panel dock line edit widget state setting """

        self.nameLineEdit.setReadOnly(state)
        self.ipLineEdit.setReadOnly(state)
        self.macLineEdit.setReadOnly(state)
        self.vendorLineEdit.setReadOnly(state)
        self.netmaskLineEdit.setReadOnly(state)

        self.gwIpLineEdit.setReadOnly(state)
        self.gwMacLineEdit.setReadOnly(state)
        self.gwVendorLineEdit.setReadOnly(state)

    def remainWidgetInit(self):
        """ Scan Dock, conciseTable, verboseTab, decodeTab initial """

        # Scan dock
        self.scanDock.setWindowTitle('Scan panel: ')
        self.stopButton.setEnabled(False)

        # conciseTable
        self.conciseInfoTable.setEnabled(False)

        # verboseTabs
        self.linkTab.setEnabled(False)
        self.interTab.setEnabled(False)
        self.transTab.setEnabled(False)
        self.appTab.setEnabled(False)
        self.verboseInfoTab.setEnabled(False)

        # decode tabs
        self.rawTab.setEnabled(False)
        self.hexTab.setEnabled(False)
        self.decodeInfoTab.setEnabled(False)

    def clearAllText(self):
        """ Clear all the text in the widget """

        # Controal tabs
        self._clearCtlTabsText()

        # NodeList
        self.nodeListWidget.clear()
        # fix bug --> analysis button text init1ial
        self.analysisButton.setText('analysis')
        self.analysisButton.setEnabled(False)
        self.action_Start.setEnabled(False)

        # Concise Table
        self.conciseInfoTable.clearContents()

        # Verbose tabs
        self.linkTextEdit.clear()
        self.interTextEdit.clear()
        self.TransTextEdit.clear()

        # Decode tabs
        self.appTextEdit.clear()
        self.rawTextEdit.clear()
        self.hexTextEdit.clear()

    def _clearCtlTabsText(self):
        """ Clean control panel tabs text info """

        # Network tab
        self.nameLineEdit.clear()
        self.ipLineEdit.clear()
        self.macLineEdit.clear()
        self.vendorLineEdit.clear()
        self.netmaskLineEdit.clear()
        self.gwIpLineEdit.clear()
        self.gwMacLineEdit.clear()
        self.gwVendorLineEdit.clear()

        # Scan tab
        self.rangeLineEdit.clear()
        self.maskLineEdit.clear()

        # Search tab
        self.searchLineEdit.clear()

        # Query tab
        self.sipLineEdit.clear()
        self.sipTextEdit.clear()

    def clearStatusBarText(self):
        """ Status bar text initial """

        self.uploadLabel.setText('upload:  KB |')
        self.downloadLabel.setText('download:  KB |')
        self.packageSentLabel.setText('sent: packages |')
        self.packageRecveLabel.setText('receive: packages')


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    spruce = ShineMainWindow()
    spruce.show()
    sys.exit(app.exec_())
