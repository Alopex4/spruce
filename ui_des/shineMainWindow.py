#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess

import requests
from PyQt5 import QtWidgets
from PyQt5 import QtGui
from PyQt5 import QtCore

from mainWindow import Ui_MainWindow
from shineDialog import Ui_RankDialog
from shineDialog import Ui_AuthorDialog

ROOT = 1
NETWORK = 2
ROUTING = 4
TCPDUMP = 8


class ShineMainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    # range scan regular express
    rangeRegex = ("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-"
                  "([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    # mask scan regular express
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
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
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

        self.scanProgressBar.setMinimum = 100
        self.scanProgressBar.setMaximum = 100
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
        self.speedLabel = QtWidgets.QLabel('')
        self.speedLabel.setText('↑upload  || ↓download')
        self.statusBar.addPermanentWidget(self.speedLabel)
        self.setStatusBar(self.statusBar)

    def shineInitUI(self):
        """ Initial all the widget status
            1. define the rank
                * root privilege  --> without affect --> application error      --> value 0000 0001
                * network startup --> without affect --> without ipinfo search  --> value 0000 0010
                * ip routing      --> without affect --> without remote sniffer --> value 0000 0100
                * tcpdump install --> without affect --> without filter feature --> value 0000 1000
            2. action trigger connect
            3. widget status initial
        """

        # Task 1
        # Define the rank
        self.rank = self.getRank()

        # Task 2
        # Action tiggered connect
        self.action_close.triggered.connect(self.close)
        self.action_Rank.triggered.connect(self.showRankDialog)
        self.action_Save.triggered.connect(self.showSaveFile)
        self.action_Open.triggered.connect(self.showOpenFile)
        self.action_Author.triggered.connect(self.showAuthorDialog)

        # Task 3
        # Control Dock initial
        self.ctlDockLineEditSet(False)
        self.ctlPanelTabSwitch()
        self.ctlPanelContInit()
        self.ctlRemainInit()
        self.unlockButton.clicked.connect(self.unlockTrigger)

    # ---------------
    # define the rank
    # ---------------
    def getRank(self):
        """ Manage the rank info """

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
        except requests.ConnectionError:
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
    def showRankDialog(self):
        """ 
            Menubar --> About --> &rank 
            show root, network, routing, tcpdump all right or not
        """

        self.rank = self.getRank()
        rankDialog = Ui_RankDialog(self)
        true_ico = QtGui.QPixmap('../true.ico')
        false_ico = QtGui.QPixmap('../false.ico')

        # Use `and` operator to get current active level
        statue_list = [
            true_ico if self.rank & i == i else false_ico
            for i in [ROOT, NETWORK, ROUTING, TCPDUMP]
        ]
        rankDialog.rootStateLabel.setPixmap(statue_list.pop(0))
        rankDialog.netStateLabel.setPixmap(statue_list.pop(0))
        rankDialog.routingStateLabel.setPixmap(statue_list.pop(0))
        rankDialog.dumpStateLabel.setPixmap(statue_list.pop(0))

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

    def _exportFmtTpl(self, dialogName, fileFilter, dirctory='.'):
        """ 
            Menubar --> File --> export ---> ... 
            Export csv, json, plaint text format template 
        """

        # _ -> file type
        saveFileName, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, dialogName, dirctory, fileFilter)
        return saveFileName

    # --------------
    # widget initial
    # --------------
    def ctlDockLineEditSet(self, state=False):
        """ Control panel dock line edit widget state setting """

        self.nameLineEdit.setEnabled(state)
        self.ipLineEdit.setEnabled(state)
        self.macLineEdit.setEnabled(state)
        self.vendorLineEdit.setEnabled(state)
        self.netmaskLineEdit.setEnabled(state)

        self.gwIpLineEdit.setEnabled(state)
        self.gwMacLineEdit.setEnabled(state)
        self.gwVendorLineEdit.setEnabled(state)

    def unlockTrigger(self):
        """ Unlock/Lock the network tab editline box """

        situation = self.unlockButton.text()
        if situation == 'unlock':
            self.ctlDockLineEditSet(True)
            self.unlockButton.setText('lock')
        elif situation == 'lock':
            self.ctlDockLineEditSet(False)
            self.unlockButton.setText('unlock')

    def ctlPanelTabSwitch(self):
        """
            Control panel tab widget active/deactive, according to the rank level
            NETWORK --> search tab, ipinfo tab
            ROOT, NETWORK --> network tab, scan tab
            ROOT, NETWORK, TCPDUMP --> filter tab
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

        if ((ROOT | NETWORK | TCPDUMP) & self.rank) == (ROOT | NETWORK
                                                        | TCPDUMP):
            self.filterTab.setEnabled(True)
        else:
            self.filterTab.setEnabled(False)

    def ctlPanelContInit(self):
        """ 
            Control panel all contain widget need a initial status
            NetworkTab --> lock all lineEdit
            ScanTab --> paceholder and match pattern(range: 192.168.1.1-100, 
                mask: 192.168.1.1/24)
            FilterTab --> auto choose `all` 
            SearchTab --> paceholder and tips
            ipinfo --> paceholder and tips 
        """
        # Network Tab
        self.ctlDockLineEditSet(False)

        # Scan Tab
        self.rangeLineEdit.setPlaceholderText('eg: 192.168.1-100')
        rangeRegex = QtCore.QRegExp(ShineMainWindow.rangeRegex)
        rangeValidator = QtGui.QRegExpValidator(rangeRegex, self.rangeLineEdit)
        self.rangeLineEdit.setValidator(rangeValidator)
        self.rangeLineEdit.setToolTip('Input Example: 192.168.1.1-100')
        self.rangeLineEdit.setAlignment(QtCore.Qt.AlignCenter)

        self.maskLineEdit.setPlaceholderText('eg: 192.168.1/24')
        maskRegex = QtCore.QRegExp(ShineMainWindow.maskRegex)
        maskValidator = QtGui.QRegExpValidator(maskRegex, self.maskLineEdit)
        self.maskLineEdit.setValidator(maskValidator)
        self.maskLineEdit.setToolTip('Input Example: 192.168.1.1/24')
        self.maskLineEdit.setAlignment(QtCore.Qt.AlignCenter)

        # Filter tab
        self.allRadioButton.setChecked(True)
        self.intGroupBox.setEnabled(False)
        self.TranGroupBox.setEnabled(False)
        self.appGroupBox.setEnabled(False)

    def ctlRemainInit(self):
        """Scan Dock, conciseTable, verboseTab, decodeTab initial"""

        self.scanDock.setEnabled(False)
        self.conciseInfoTable.setEnabled(False)
        self.verboseInfoTab.setEnabled(False)
        self.decodeInfoTab.setEnabled(False)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    spruce = ShineMainWindow()
    spruce.show()
    sys.exit(app.exec_())
