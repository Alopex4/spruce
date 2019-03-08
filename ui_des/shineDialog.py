#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from PyQt5 import QtCore, QtGui, QtWidgets

from rankDialog import Ui_Form as shineRankDialoge
from authorDialog import Ui_Dialog as shineAuthorDialog
from filterDialog import Ui_Dialog as shineFilterDialog


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

    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
        self.setWindowTitle('packets filter')
        self.setFixedSize(260, 420)
        self.disableRadio.clicked.connect(
            lambda: self.widgetManage(False, False, False, reset=True))
        self.enableRaido.clicked.connect(
            lambda: self.widgetManage(True, True, False, reset=True))

        self.customCheckBox.clicked.connect(self.customStatus)

        self.buttonBox.clicked.connect(lambda: self.setFilter('clicked hit'))
        self.buttonBox.rejected.connect(lambda: self.setFilter('rejectd hit'))
        self.disableRadio.click()

    def setFilter(self, text):
        print(text)

    def customStatus(self):
        status = self.customCheckBox.checkState()
        if status == QtCore.Qt.Unchecked:
            self.widgetManage(True, True, False)
        elif status == QtCore.Qt.Checked:
            self.widgetManage(False, True, True)

    def widgetManage(self, status, checkbox, lineedit, reset=False):
        self._containsUnlock(status)
        self.customCheckBox.setEnabled(checkbox)
        self.customLineEdit.setEnabled(lineedit)
        if reset:
            self._resetWidget()

    def _resetWidget(self):
        self.customCheckBox.setCheckState(QtCore.Qt.Unchecked)
        self.customLineEdit.clear()
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

    def _containsUnlock(self, status):
        self.intGroupBox.setEnabled(status)
        self.tranGroupBox.setEnabled(status)
        self.appGroupBox.setEnabled(status)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    author = ui_FilterDialog()
    author.show()
    sys.exit(app.exec_())