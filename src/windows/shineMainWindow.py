#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import subprocess

# import requests
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5 import QtWidgets

from src.windows.mainWindow import Ui_MainWindow
from src.dialogs.shineDialog import Ui_RankDialog
from src.dialogs.shineDialog import Ui_AuthorDialog
from src.dialogs.shineDialog import Ui_HelpDialog

ROOT = 1
NETWORK = 2
ROUTING = 4
TCPDUMP = 8


class NoFocusDelegate(QtWidgets.QStyledItemDelegate):
    def paint(self, QPainter, QStyleOptionViewItem, QModelIndex):
        if QStyleOptionViewItem.state & QtWidgets.QStyle.State_HasFocus:
            QStyleOptionViewItem.state = QStyleOptionViewItem.state ^ QtWidgets.QStyle.State_HasFocus
        super().paint(QPainter, QStyleOptionViewItem, QModelIndex)


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

    fileLoc = os.path.split(os.path.realpath(__file__))[0]
    mainUpperDir = os.path.abspath(os.path.join(fileLoc, "../"))
    upperDir = os.path.abspath(os.path.join(fileLoc, "../.."))
    iconDir = '{}/{}'.format(upperDir, 'icon')

    def __init__(self, parent=None):
        super(QtWidgets.QMainWindow, self).__init__(parent)
        self.setupUi(self)
        self.shineUI()

    def shineUI(self):
        """ Make the UI looks more beauty and initial the UI status """

        self.shineBegin()
        self.shineMenu()
        self.shineDock()
        self.shineScanPanel()
        self.shineTable()
        self.shineStatusBar()
        self.shineInitUI()

    def shineBegin(self):
        """ 1. Set a prefect size (golden ration)
            2. Set a window title
            3. Set an icon
            4. Adjust window in central of the screen
        """

        # Task 1 1:0.61803
        self.resize(1000, 618)
        # Task 2
        self.setWindowTitle('spruce -- a versatile network sniffer')
        # Task 3
        spruceIcon = '{}/{}'.format(ShineMainWindow.iconDir, 'spruce.ico')
        self.setWindowIcon(QtGui.QIcon(spruceIcon))
        # Task 4
        screen = QtWidgets.QDesktopWidget().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) / 2,
                  (screen.height() - size.height()) / 2)

    def shineMenu(self):
        """
            Set the menu icon
            Set the menu hot key
        """

        # Set menu icon
        saveFile = '{}/{}'.format(ShineMainWindow.iconDir, 'save.ico')
        saveIcon = QtGui.QIcon(saveFile)
        self.action_Save.setIcon(saveIcon)

        openFile = '{}/{}'.format(ShineMainWindow.iconDir, 'open.ico')
        openIcon = QtGui.QIcon(openFile)
        self.action_Open.setIcon(openIcon)

        self.action_CtrlPan.setCheckable(True)
        self.action_CtrlPan.setChecked(True)
        self.action_ScanPan.setCheckable(True)
        self.action_ScanPan.setChecked(True)

        exitFile = '{}/{}'.format(ShineMainWindow.iconDir, 'exit.ico')
        exitIcon = QtGui.QIcon(exitFile)
        self.action_close.setIcon(exitIcon)

        startFile = '{}/{}'.format(ShineMainWindow.iconDir, 'start.ico')
        startIcon = QtGui.QIcon(startFile)
        self.action_Start.setIcon(startIcon)

        stopFile = '{}/{}'.format(ShineMainWindow.iconDir, 'stop.ico')
        stopIcon = QtGui.QIcon(stopFile)
        self.action_Stop.setIcon(stopIcon)

        restartFile = '{}/{}'.format(ShineMainWindow.iconDir, 'restart.ico')
        restartIcon = QtGui.QIcon(restartFile)
        self.action_Restart.setIcon(restartIcon)

        filterFile = '{}/{}'.format(ShineMainWindow.iconDir, 'filter.ico')
        filterIcon = QtGui.QIcon(filterFile)
        self.action_Filter.setIcon(filterIcon)

        ioFile = '{}/{}'.format(ShineMainWindow.iconDir, 'io.ico')
        ioIcon = QtGui.QIcon(ioFile)
        self.action_IOflow.setIcon(ioIcon)

        updonwFile = '{}/{}'.format(ShineMainWindow.iconDir, 'updown.ico')
        updownIcon = QtGui.QIcon(updonwFile)
        self.action_Speed.setIcon(updownIcon)

        globalFile = '{}/{}'.format(ShineMainWindow.iconDir, 'global.ico')
        globalIcon = QtGui.QIcon(globalFile)
        self.action_Gobal.setIcon(globalIcon)

        addrFile = '{}/{}'.format(ShineMainWindow.iconDir, 'addr.ico')
        addrIcon = QtGui.QIcon(addrFile)
        self.action_Addr.setIcon(addrIcon)

        layerFile = '{}/{}'.format(ShineMainWindow.iconDir, 'layer.ico')
        layerIcon = QtGui.QIcon(layerFile)
        self.action_Layer.setIcon(layerIcon)

        protsFile = '{}/{}'.format(ShineMainWindow.iconDir, 'prots.ico')
        protsIcon = QtGui.QIcon(protsFile)
        self.action_Type.setIcon(protsIcon)

        allFile = '{}/{}'.format(ShineMainWindow.iconDir, 'all.ico')
        allIcon = QtGui.QIcon(allFile)
        self.action_PktLen.setIcon(allIcon)

        tcpFile = '{}/{}'.format(ShineMainWindow.iconDir, 'tcp.ico')
        tcpIcon = QtGui.QIcon(tcpFile)
        self.action_TCPPktLen.setIcon(tcpIcon)

        udpFile = '{}/{}'.format(ShineMainWindow.iconDir, 'udp.ico')
        udpIcon = QtGui.QIcon(udpFile)
        self.action_UDPPktLen.setIcon(udpIcon)

        authorFile = '{}/{}'.format(ShineMainWindow.iconDir, 'author.ico')
        authorIcon = QtGui.QIcon(authorFile)
        self.action_Author.setIcon(authorIcon)

        refreshFile = '{}/{}'.format(ShineMainWindow.iconDir, 'refresh.ico')
        refreshIcon = QtGui.QIcon(refreshFile)
        self.action_RefreshRank.setIcon(refreshIcon)

        rankFile = '{}/{}'.format(ShineMainWindow.iconDir, 'rank.ico')
        rankIcon = QtGui.QIcon(rankFile)
        self.action_Rank.setIcon(rankIcon)

        helpFile = '{}/{}'.format(ShineMainWindow.iconDir, 'help.ico')
        helpIcon = QtGui.QIcon(helpFile)
        self.action_Help.setIcon(helpIcon)

        # set hot key
        self.action_Open.setShortcut('Ctrl+O')
        self.action_Save.setShortcut('Ctrl+S')
        self.action_RefreshRank.setShortcut('Ctrl+R')
        self.action_close.setShortcut('Ctrl+Q')
        self.action_Filter.setShortcut('Ctrl+F')
        self.action_Start.setShortcut('Ctrl+Shift+S')
        self.action_Stop.setShortcut('Ctrl+Shift+P')
        self.action_Restart.setShortcut('Ctrl+Shift+R')
        self.action_Help.setShortcut('F1')
        self.action_Author.setShortcut('F2')
        self.action_Rank.setShortcut('F3')

    def shineDock(self):
        """ Set dock widget movable and floatable """

        self.controlDock.setFeatures(
            QtWidgets.QDockWidget.DockWidgetMovable
            | QtWidgets.QDockWidget.DockWidgetFloatable
            | QtWidgets.QDockWidget.DockWidgetClosable)

        self.scanDock.setFeatures(
            QtWidgets.QDockWidget.DockWidgetMovable
            | QtWidgets.QDockWidget.DockWidgetFloatable
            | QtWidgets.QDockWidget.DockWidgetClosable)

    def shineScanPanel(self):
        """ Set scan panel look much better """

        # http://blog.sina.com.cn/s/blog_a6fb6cc90101dd5u.html
        # Remove the dotted border also keep the key focus
        self.nodeListWidget.setItemDelegate(NoFocusDelegate())
        # Remove the dotted border and give up the key focus
        # self.nodeListWidget.setFocusPolicy(QtCore.Qt.NoFocus)
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
        # Text don't wrap
        self.conciseInfoTable.setWordWrap(False)
        # Remove the dotted border but give up the key focus
        # self.conciseInfoTable.setFocusPolicy(QtCore.Qt.NoFocus)
        # Remove the dotted border also keey the key focus
        self.conciseInfoTable.setItemDelegate(NoFocusDelegate())
        # Remove focuse in title
        self.conciseInfoTable.horizontalHeader().setHighlightSections(False)

        # auto seperate field
        # self.conciseInfoTable.horizontalHeader().setSectionResizeMode(
        #     QtWidgets.QHeaderView.Stretch)
        # self.conciseInfoTable.setColumnWidth()

    def shineStatusBar(self):
        """ Set a label widget the monitor the download/upload status"""

        self.statusBar = QtWidgets.QStatusBar(self)
        self.statusBar.setFixedHeight(35)
        filterFile = '{}/{}'.format(ShineMainWindow.iconDir, 'filter.ico')
        filterIco = QtGui.QPixmap(filterFile)
        uploadFile = '{}/{}'.format(ShineMainWindow.iconDir, 'upload.ico')
        uploadIco = QtGui.QPixmap(uploadFile)
        downloadFile = '{}/{}'.format(ShineMainWindow.iconDir, 'download.ico')
        downloadIco = QtGui.QPixmap(downloadFile)
        packageSentFile = '{}/{}'.format(ShineMainWindow.iconDir,
                                         'packageSent.ico')
        packageSentIco = QtGui.QPixmap(packageSentFile)
        packageRecvFile = '{}/{}'.format(ShineMainWindow.iconDir,
                                         'packageRecv.ico')
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
            4. tabs focus point
        """

        # Task 1
        self.rank = self.getRank()
        # Task 2
        self.triggerInit()
        # Task 3
        self.allWidgetInit()
        # Task 4
        self.tabsFocus()

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

        host = '114.114.114.114'
        port = 53
        try:
            # socket.setdefaulttimeout(1)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host,
                                                                       port))
            return 2
        except Exception:
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
        """ menu static acion trigger initial """

        self.action_close.triggered.connect(self.close)
        self.action_Rank.triggered.connect(self.showRankDialog)
        self.action_Author.triggered.connect(self.showAuthorDialog)
        self.action_RefreshRank.triggered.connect(self.refreshRank)
        self.action_Help.triggered.connect(self.helpDialog)

    def showRankDialog(self):
        """
            Menubar --> About --> &rank
            show root, network, routing, tcpdump all right or not
        """

        self.rank = self.getRank()
        rankDialog = Ui_RankDialog(self)

        trueFile = '{}/{}'.format(ShineMainWindow.iconDir, 'true.ico')
        trueIco = QtGui.QPixmap(trueFile)
        falseFile = '{}/{}'.format(ShineMainWindow.iconDir, 'false.ico')
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

    def showAuthorDialog(self):
        """
            Menubar --> About --> &author
            show author dialog information
        """

        auhtorDialog = Ui_AuthorDialog(self)
        auhtorDialog.exec_()

    def refreshRank(self):
        """
            Menubar --> Option --> &refresh rank
            1. refresh the rank
            2. clear all the text
        """

        self.rank = self.getRank()
        self.allWidgetInit()

    def helpDialog(self):
        """ Display the help information """

        staticDir = '{}/{}'.format(self.upperDir, 'static')
        helpFile = '{}/{}'.format(staticDir, 'help.html')
        self.helpDialog = Ui_HelpDialog()
        with open(helpFile, 'r') as f:
            pageText = f.read()
            self.helpDialog.helpTextBro.setText(pageText)

        self.helpDialog.exec_()

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
        self.menu_flow.setEnabled(False)
        self.menu_protocol.setEnabled(False)
        self.menu_length.setEnabled(False)

    def ctlPanelTabSwitch(self):
        """
            Control panel tab widget active/deactive, according to the rank level
            NETWORK --> search tab, ipinfo tab
            ROOT, NETWORK --> network tab, scan tab, term tab
        """

        if self.rank & NETWORK == NETWORK:
            self.searchTab.setEnabled(True)
            self.ipinfoTab.setEnabled(True)
            self.termTab.setEnabled(True)
        else:
            self.searchTab.setEnabled(False)
            self.ipinfoTab.setEnabled(False)
            self.termTab.setEnabled(False)

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
        self.rangeLineEdit.setPlaceholderText('eg: 192.168.1.0-10')
        self.rangeLineEdit.setToolTip('Input example: 192.168.1.0-10')
        self.rangeLineEdit.setStatusTip('Specific your scan ip range.')
        self.rangeLineEdit.setAlignment(QtCore.Qt.AlignCenter)

        maskRegexExp = QtCore.QRegExp(ShineMainWindow.maskRegex)
        maskValidator = QtGui.QRegExpValidator(maskRegexExp, self.maskLineEdit)
        self.maskLineEdit.setValidator(maskValidator)
        self.maskLineEdit.setPlaceholderText('eg: 192.168.0/24')
        self.maskLineEdit.setToolTip('Input Example: 192.168.1.0/24')
        self.maskLineEdit.setStatusTip('Specific your scan ip mask.')
        self.maskLineEdit.setAlignment(QtCore.Qt.AlignCenter)

        # Search Tab
        self.searchLineEdit.setPlaceholderText('eg: ethernet.ip.tcp.http')
        self.searchLineEdit.setToolTip('Specific protocol you want to display')
        self.searchLineEdit.setStatusTip(
            'Display the specific protocol after you stop analysis')
        self.searchButton.setEnabled(False)

        # Info Tab
        ipRegexExp = QtCore.QRegExp(ShineMainWindow.ipRegex)
        ipValidator = QtGui.QRegExpValidator(ipRegexExp, self.sipLineEdit)
        self.sipLineEdit.setValidator(ipValidator)
        self.sipLineEdit.setPlaceholderText('eg: 8.8.8.8')
        self.sipLineEdit.setToolTip('Input Example: 8.8.8.8')
        self.sipLineEdit.setStatusTip(
            'Specific an ip you want to query (defulat: query your public ip)')

        demoQueryText = """{
    "as": "AS15169 Google LLC",
    "city": "Mountain View",
    "country": "United States",
    "countryCode": "US",
    "isp": "Level 3 Communications",
    "lat": 37.4229,
    "lon": -122.085,
    "org": "Google Inc.",
    "query": "8.8.8.8",
    "region": "CA",
    "regionName": "California",
    "status": "success",
    "timezone": "America/Los_Angeles",
    "zip": "94043"
}
        """
        self.sipTextEdit.setPlaceholderText(demoQueryText)
        self.sipTextEdit.setReadOnly(True)

        # Term Tab
        self.termLineEdit.setPlaceholderText('eg: linux')
        self.termLineEdit.setToolTip('Input example: linux')
        self.termLineEdit.setStatusTip(
            'Query computer terminology you want to know.')
        demoTermText = """
    <p>Linux (pronounced "lih-nux", not "lie-nux") is a Unix-like 
    <a href="/definition/operating_system">operating system</a> (OS) 
    created by Linus Torvalds. He developed Linux because he wasn't 
    happy with the currently available options in
     <a href="/definition/unix">Unix</a> and felt he could improve it. 
     So he did what anybody else would do, and created his own operating system.</p>
    <p>When Linus finished building a working version of Linux, he freely 
    distributed the OS, which helped it gain popularity.  Today, Linux is 
    used by millions of people around the world.  Many computer hobbyists 
    (a.k.a. nerds) like the operating system because it is highly 
    customizable.  Programmers can even modify the 
    <a href="/definition/sourcecode">source code</a> and create their own 
    unique version of the Linux operating system.</p>
        """
        self.termTextEdit.setText(demoTermText)
        self.termTextEdit.setReadOnly(True)

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
        startFile = '{}/{}'.format(ShineMainWindow.iconDir, 'start.ico')
        startIcon = QtGui.QIcon(startFile)
        self.analysisButton.setIcon(startIcon)

        stopFile = '{}/{}'.format(ShineMainWindow.iconDir, 'stop.ico')
        stopIcon = QtGui.QIcon(stopFile)
        self.stopButton.setIcon(stopIcon)

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
        self.rawTextEdit.setReadOnly(True)
        self.utfTab.setEnabled(False)
        self.utfTextEdit.setReadOnly(True)
        self.decodeInfoTab.setEnabled(False)

    def clearAllText(self):
        """ Clear all the text in the widget """

        # Controal tabs
        self._clearCtlTabsText()

        # NodeList
        self.nodeListWidget.clear()
        # fix bug --> analysis button text initial
        self.analysisButton.setText('analysis')
        self.analysisButton.setEnabled(False)
        self.action_Start.setEnabled(False)

        # Concise Table
        self.conciseInfoTable.clearContents()

        # Verbose tabs
        self.linkTextEdit.clear()
        self.interTextEdit.clear()
        self.transTextEdit.clear()
        self.appTextEdit.clear()

        # Decode tabs
        self.rawTextEdit.clear()
        self.utfTextEdit.clear()

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

        # Terms tab
        self.termLineEdit.clear()

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

    def clearStatusBarText(self):
        """ Status bar text initial """

        self.uploadLabel.setText('upload:  KB |')
        self.downloadLabel.setText('download:  KB |')
        self.packageSentLabel.setText('sent: packages |')
        self.packageRecveLabel.setText('receive: packages')

    def tabsFocus(self):
        """ Set tabs focuse button """

        self.refreshButton.setDefault(True)
        self.rangeButton.setDefault(True)
        self.maskButton.setDefault(True)
        self.searchButton.setDefault(True)
        self.sipButton.setDefault(True)
        self.termButton.setDefault(True)

        self.analysisButton.setDefault(True)
        self.stopButton.setDefault(True)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    spruce = ShineMainWindow()
    spruce.show()
    sys.exit(app.exec_())
