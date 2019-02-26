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
from rankDialog import Ui_RankDialog


class ShineMainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
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
        rootPrivilege = self.rootPrivilegeCheck()
        networkStartUp = self.networkStartUpCheck()
        ipRouting = self.ipRoutingCheck()
        tcpdumpState = self.tcpdumpCheck()
        self.rank = rootPrivilege | networkStartUp | ipRouting | tcpdumpState

        # Task 2
        self.action_close.triggered.connect(self.close)
        self.action_Rank.triggered.connect(self.showRankDialog)
        self.action_Save.triggered.connect(self.showSaveFile)
        self.action_Open.triggered.connect(self.showOpenFile)

        self.unlockButton.clicked.connect(self.unlockTrigger)

        # Task 3
        # Control Dock initial
        self.ctlDockLineEditSet(False)

        # Scan Dock, conciseTable, verboseTab, decodeTab initial
        self.scanDock.setEnabled(False)
        self.conciseInfoTable.setEnabled(False)
        self.verboseInfoTab.setEnabled(False)
        self.decodeInfoTab.setEnabled(False)

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
        situation = self.unlockButton.text()
        if situation == 'unlock':
            self.ctlDockLineEditSet(True)
            self.unlockButton.setText('lock')
        elif situation == 'lock':
            self.ctlDockLineEditSet(False)
            self.unlockButton.setText('unlock')

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

    def showRankDialog(self):
        """ 
            Menubar --> About --> &rank 
            show root, network, routing, tcpdump all right or not
        """

        rankDialog = Ui_RankDialog(self)
        true_ico = QtGui.QPixmap('../true.ico')
        false_ico = QtGui.QPixmap('../false.ico')

        # Use `and` operator to get current active level
        statue_list = [
            true_ico if self.rank & i == i else false_ico
            for i in [1, 2, 4, 8]
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


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    spruce = ShineMainWindow()
    spruce.show()
    sys.exit(app.exec_())
