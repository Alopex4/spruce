#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from time import sleep

from src.dialogs.rankDialog import Ui_Form as shineRankDialoge
from src.dialogs.authorDialog import Ui_Dialog as shineAuthorDialog
from src.dialogs.filterDialog import Ui_Dialog as shineFilterDialog
from src.dialogs.nodeDialog import Ui_Dialog as shineNodeDialog
from src.dialogs.loadDialog import Ui_Dialog as shineLoadDialog
from src.dialogs.statisticDialog import StatisticDialog as shineStatisticDialog
from src.dialogs.helpDialog import Ui_Dialog as shineHelpDialog


# from rankDialog import Ui_Form as shineRankDialoge
# from authorDialog import Ui_Dialog as shineAuthorDialog
# from filterDialog import Ui_Dialog as shineFilterDialog
# from nodeDialog import Ui_Dialog as shineNodeDialog
# from loadDialog import Ui_Dialog as shineLoadDialog
# from statisticDialog import StatisticDialog as shineStatisticDialog
# from helpDialog import Ui_Dialog as shineHelpDialog


class IconLoc:
    """ Define the icon location """

    fileLoc = os.path.split(os.path.realpath(__file__))[0]
    upperDir = os.path.abspath(os.path.join(fileLoc, "../.."))
    iconDir = '{}/{}'.format(upperDir, 'icon')


class Ui_RankDialog(QtWidgets.QDialog, shineRankDialoge):
    """
        Rank dialog widget.
        Check root privilege, network status, ip routing, tcpdump install
    """

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        # self.setWindowIcon(QtGui.QIcon(IconLoc.appIconDir))
        self.setWindowTitle('current state')
        self.setFixedSize(220, 136)

        self.rootStateLabel.clear()
        self.netStateLabel.clear()
        self.routingStateLabel.clear()
        self.dumpStateLabel.clear()

        self.rootLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.rootStateLabel.setAlignment(QtCore.Qt.AlignCenter)

        self.netLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.netStateLabel.setAlignment(QtCore.Qt.AlignCenter)

        self.routingLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.routingStateLabel.setAlignment(QtCore.Qt.AlignCenter)

        self.dumpLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.dumpStateLabel.setAlignment(QtCore.Qt.AlignCenter)


class Ui_AuthorDialog(QtWidgets.QDialog, shineAuthorDialog, IconLoc):
    """
        Author dialog widget.
        Display the author informaiton
        include project webside, author contact
    """

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)

        parentDir = IconLoc.iconDir
        spruceFile = '{}/{}'.format(parentDir, 'spruce.ico')
        spruceIco = QtGui.QPixmap(spruceFile)

        # self.setWindowIcon(QtGui.QIcon(spruceIco))
        self.setWindowTitle('about author')
        self.setFixedSize(272, 440)
        self.iconLabel.clear()
        self.iconLabel.setPixmap(spruceIco)

        self.authorLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.contacLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.contacLabel.setOpenExternalLinks(True)
        self.projectLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.projectLabel.setOpenExternalLinks(True)
        self.versionLabel.setAlignment(QtCore.Qt.AlignCenter)


class ui_FilterDialog(QtWidgets.QDialog, shineFilterDialog):
    """
        Filter dialog widget.
        Pass info to tcpdump generate an filter codes.
    """

    filterSignal = QtCore.pyqtSignal(dict)

    def __init__(self, filterDict, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        # {'type': 'noncustom', 'filter': ''}
        self.recvFilterDict = filterDict

        self.setupUi(self)
        self.initUi()
        self.signalSlotMap()
        self.filterInit()

    def initUi(self):
        """ Initial the filter dialog UI """

        self.setWindowTitle('packets filter')
        self.setFixedSize(260, 420)

    def signalSlotMap(self):
        """ Mapping the signal and slot """

        self.disableRadio.clicked.connect(
            lambda: self.widgetManage(False, False, False, reset=True))
        self.enableRaido.clicked.connect(
            lambda: self.widgetManage(True, True, False, reset=True))

        # self.customCheckBox.clicked.connect(self.customStatus)
        self.customCheckBox.toggled.connect(self.customStatus)
        self.buttonBox.accepted.connect(self.structFilter)
        self.buttonBox.rejected.connect(self.formerFilter)

    def customStatus(self):
        """ Maping to the custome checkbox click """

        status = self.customCheckBox.checkState()
        if status == QtCore.Qt.Unchecked:
            self.widgetManage(True, True, False)
        elif status == QtCore.Qt.Checked:
            self.widgetManage(False, True, True)

    def widgetManage(self, status, checkbox, lineedit, reset=False):
        """ Manage the protocol layer, checkbox and lineedit status """

        self._protUnlock(status)
        self.customCheckBox.setEnabled(checkbox)
        self.customLineEdit.setEnabled(lineedit)
        if reset:
            self._resetWidget()

    def _protUnlock(self, status):
        """ Protocl layer unlock or lock """

        self.intGroupBox.setEnabled(status)
        self.tranGroupBox.setEnabled(status)
        self.appGroupBox.setEnabled(status)

    def _resetWidget(self):
        """ reset all the widget to initial status (remove marks and texts) """

        # Remove marks
        self.customCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.ipCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.icmpCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.igmpCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.udpCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.tcpCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.ftpCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.telnetCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.sshCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.dnsCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.httpsCheckBox.setCheckState(QtCore.Qt.Unchecked)

        # Remove texts
        self.customLineEdit.clear()

    def filterInit(self):
        """ Initial fiter according to filterDict """

        # {'type': 'noncustom', 'filter': ''}
        if self.recvFilterDict['filter'] == '':
            self.disableRadio.click()
        elif self.recvFilterDict['type'] == 'custom':
            self._setCustomLine()

        elif self.recvFilterDict['type'] == 'noncustom':
            self._setFilterCheck()

    def _setCustomLine(self):
        """ Custom line edit setting """

        self.enableRaido.setChecked(True)
        self.customCheckBox.click()
        self.customLineEdit.setText(self.recvFilterDict['filter'])
        # self.customLineEdit.setEnabled(True)
        # self._protUnlock(False)

    def _setFilterCheck(self):
        """ Protocol checkbox setting """

        self.enableRaido.setChecked(True)
        self.customCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.customLineEdit.setEnabled(False)
        filterString = self.recvFilterDict['filter']
        filterTuple = tuple(
            filter(None,
                   filterString.replace('port ', '').split('||')))

        if 'ip ' in filterTuple:
            self.ipCheckBox.setChecked(True)
        if 'icmp ' in filterTuple:
            self.icmpCheckBox.setChecked(True)
        if 'igmp ' in filterTuple:
            self.igmpCheckBox.setChecked(True)

        if 'udp ' in filterTuple:
            self.udpCheckBox.setChecked(True)
        if 'tcp ' in filterTuple:
            self.tcpCheckBox.setChecked(True)

        if '20 ' in filterTuple:
            self.ftpCheckBox.setChecked(True)
        if '22 ' in filterTuple:
            self.sshCheckBox.setChecked(True)
        if '23 ' in filterTuple:
            self.telnetCheckBox.setChecked(True)
        if '53 ' in filterTuple:
            self.dnsCheckBox.setChecked(True)
        if '80 ' in filterTuple:
            self.httpsCheckBox.setChecked(True)

    def structFilter(self):
        """
            Struct the filter string
            type: 
                customCheckBox --> checked custom
                                 unckecked noncustom
            filterString -->  
                    --> custom
                        scan custom lineEdit
                    --> noncustom
                        scan all the layout box
        """

        if self.customCheckBox.checkState() == QtCore.Qt.Checked:
            self.recvFilterDict['type'] = 'custom'
            self.recvFilterDict['filter'] = self.customLineEdit.text().strip()
        else:
            self.recvFilterDict['type'] = 'noncustom'
            if self.enableRaido.isEnabled():
                self.recvFilterDict['filter'] = self._nonCustomFilter()
            elif self.disableRadio.isEnabled():
                self.recvFilterDict['filter'] = ''

        self.filterSignal.emit(self.recvFilterDict)
        # print(self.filterDict)

    def _nonCustomFilter(self):
        """ Scan all the checkbox to struct filter string """

        filterList = [
            'ip ', 'icmp ', 'igmp ', 'udp ', 'tcp ', 'port-20 ',
            'port-21 ', 'port-22 ', 'port-23 ', 'port-53 ',
            'port-80 ', 'port-443 '
        ]

        if not self.ipCheckBox.isChecked():
            filterList.remove('ip ')
        if not self.icmpCheckBox.isChecked():
            filterList.remove('icmp ')
        if not self.igmpCheckBox.isChecked():
            filterList.remove('igmp ')

        if not self.udpCheckBox.isChecked():
            filterList.remove('udp ')
        if not self.tcpCheckBox.isChecked():
            filterList.remove('tcp ')

        if not self.ftpCheckBox.isChecked():
            filterList.remove('port-20 ')
            filterList.remove('port-21 ')
        if not self.sshCheckBox.isChecked():
            filterList.remove('port-22 ')
        if not self.telnetCheckBox.isChecked():
            filterList.remove('port-23 ')
        if not self.dnsCheckBox.isChecked():
            filterList.remove('port-53 ')
        if not self.httpsCheckBox.isChecked():
            filterList.remove('port-80 ')
            filterList.remove('port-443 ')

        filterString = '||'.join(filterList).replace('-', ' ')
        return filterString

    def formerFilter(self):
        """ Return the former filter string """

        self.filterSignal.emit(self.recvFilterDict)


class Ui_NodeDialog(QtWidgets.QDialog, shineNodeDialog, IconLoc):
    """
        Node dialog widget.
        Display the node informaiton
    """

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle('node information')
        self.setFixedSize(247, 400)
        self._setIcons()
        self._decorateLineEdit()
        self.nodeOkButton.clicked.connect(self.close)

    def _setIcons(self):
        """ set node icons """

        parentDir = IconLoc.iconDir
        ipFile = '{}/{}'.format(parentDir, 'ip.ico')
        ipIco = QtGui.QPixmap(ipFile)
        macFile = '{}/{}'.format(parentDir, 'mac.ico')
        macIco = QtGui.QPixmap(macFile)
        vendorFile = '{}/{}'.format(parentDir, 'vendor.ico')
        vendorIco = QtGui.QPixmap(vendorFile)
        typeFile = '{}/{}'.format(parentDir, 'type.ico')
        typeIco = QtGui.QPixmap(typeFile)

        self.nodeIpIconLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.nodeIpIconLabel.setPixmap(ipIco)
        self.nodeMacIconLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.nodeMacIconLabel.setPixmap(macIco)
        self.nodeVendorIconLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.nodeVendorIconLabel.setPixmap(vendorIco)
        self.nodeTypeIconLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.nodeTypeIconLabel.setPixmap(typeIco)

    def _decorateLineEdit(self):
        """ 
            set node text read only 
            set node aligenment
        """

        self.nodeIpLineEdit.setReadOnly(True)
        self.nodeIpLineEdit.setAlignment(QtCore.Qt.AlignCenter)
        self.nodeMacLineEdit.setReadOnly(True)
        self.nodeMacLineEdit.setAlignment(QtCore.Qt.AlignCenter)
        self.nodeVendorLineEdit.setReadOnly(True)
        self.nodeVendorLineEdit.setAlignment(QtCore.Qt.AlignHCenter)
        self.nodeTypeLineEdit.setReadOnly(True)
        self.nodeTypeLineEdit.setAlignment(QtCore.Qt.AlignCenter)


class Ui_LoadDialog(QtWidgets.QDialog, shineLoadDialog, IconLoc):

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setFixedSize(272, 440)
        self.initUI()

    def initUI(self):
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        loadFile =IconLoc.iconDir + '/loading.png'
        loadMovie = QtGui.QPixmap(loadFile)
        self.moveLabel.setPixmap(loadMovie)
        self.moveLabel.setAlignment(QtCore.Qt.AlignCenter)

        statusFont = QtGui.QFont()
        statusFont.setBold(True)
        statusFont.setPointSize(16)
        self.statusLabel.setText('Pleas Wait ... ')
        self.statusLabel.setFont(statusFont)
        self.statusLabel.setAlignment(QtCore.Qt.AlignCenter)


class Ui_StatisticDialog(shineStatisticDialog):
    def __init__(self, subTitle, parent=None):
        super().__init__(parent)
        title = 'Statictic Figure: ' + subTitle
        self.setWindowTitle(title)
        self.resize(809, 500)


class Ui_HelpDialog(QtWidgets.QDialog, shineHelpDialog):

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle("Help")
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Ok)
        self.resize(480, 600)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    author = Ui_HelpDialog()
    author.show()
    sys.exit(app.exec_())
