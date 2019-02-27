#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from PyQt5 import QtCore, QtGui, QtWidgets

from rankDialog import Ui_Form as shineRankDialoge
from authorDialog import Ui_Dialog as shineAuthorDialog


class Ui_RankDialog(QtWidgets.QDialog, shineRankDialoge):
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
    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
        self.setWindowTitle('current state')
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


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    author = Ui_AuthorDialog()
    author.show()
    sys.exit(app.exec_())