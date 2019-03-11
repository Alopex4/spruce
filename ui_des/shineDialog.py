#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from PyQt5 import QtCore, QtGui, QtWidgets

from rankDialog import Ui_Form as shineRankDialoge
from authorDialog import Ui_Dialog as shineAuthorDialog
from filterDialog import Ui_Dialog as shineFilterDialog
from nodeDialog import Ui_Dialog as shineNodeDialog


class Ui_RankDialog(QtWidgets.QDialog, shineRankDialoge):
    """
        Rank dialog widget.
        Check root privilege, network status, ip routing, tcpdump install
    """

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
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


class Ui_AuthorDialog(QtWidgets.QDialog, shineAuthorDialog):
    """
        Author dialog widget.
        Display the author informaiton
        include project webside, author contact
    """

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
        self.setWindowTitle('about author')
        self.setFixedSize(272, 440)
        self.iconLabel.clear()
        author_icon = QtGui.QPixmap('../spruce.ico')
        self.iconLabel.setPixmap(author_icon)

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

        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
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
        filterString = self.recvFilterDict['filter']
        filterTuple = tuple(
            filter(None,
                   filterString.replace('dst port ', '').split('||')))

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
            self.telnetCheckBox.setChecked(True)
        if '23 ' in filterTuple:
            self.sshCheckBox.setChecked(True)
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
            'ip ', 'icmp ', 'igmp ', 'udp ', 'tcp ', 'dst-port-20 ',
            'dst-port-21 ', 'dst-port-22 ', 'dst-port-23 ', 'dst-port-53 ',
            'dst-port-80 ', 'dst-port-443 '
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
            filterList.remove('dst-port-20 ')
            filterList.remove('dst-port-21 ')
        if not self.telnetCheckBox.isChecked():
            filterList.remove('dst-port-22 ')
        if not self.sshCheckBox.isChecked():
            filterList.remove('dst-port-23 ')
        if not self.dnsCheckBox.isChecked():
            filterList.remove('dst-port-53 ')
        if not self.httpsCheckBox.isChecked():
            filterList.remove('dst-port-80 ')
            filterList.remove('dst-port-443 ')

        filterString = '||'.join(filterList).replace('-', ' ')
        return filterString

    def formerFilter(self):
        """ Return the former filter string """

        self.filterSignal.emit(self.recvFilterDict)


class Ui_NodeDialog(QtWidgets.QDialog, shineNodeDialog):
    """
        Node dialog widget.
        Display the node informaiton
    """

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
        self.setWindowTitle('node information')
        self.setFixedSize(247, 400)
        self._setIcons()
        self._decorateLineEdit()
        self.nodeOkButton.clicked.connect(self.close)

    def _setIcons(self):
        """ set node icons """

        parentDir = '..'
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


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    author = Ui_NodeDialog()
    author.show()
    sys.exit(app.exec_())