# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'author.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

import sys

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(303, 211)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.iconLabel = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("DejaVu Sans")
        self.iconLabel.setFont(font)
        self.iconLabel.setObjectName("iconLabel")
        self.verticalLayout.addWidget(self.iconLabel)
        self.authorLabel = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("DejaVu Sans")
        self.authorLabel.setFont(font)
        self.authorLabel.setObjectName("authorLabel")
        self.verticalLayout.addWidget(self.authorLabel)
        self.contacLabel = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("DejaVu Sans")
        self.contacLabel.setFont(font)
        self.contacLabel.setObjectName("contacLabel")
        self.verticalLayout.addWidget(self.contacLabel)
        self.versionLabel = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setFamily("DejaVu Sans")
        self.versionLabel.setFont(font)
        self.versionLabel.setObjectName("versionLabel")
        self.verticalLayout.addWidget(self.versionLabel)
        self.verticalLayout_2.addLayout(self.verticalLayout)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel
                                          | QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout_2.addWidget(self.buttonBox)

        self.retranslateUi(Dialog)
        self.buttonBox.accepted.connect(Dialog.accept)
        self.buttonBox.rejected.connect(Dialog.reject)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.iconLabel.setText(_translate("Dialog", "icon"))
        self.authorLabel.setText(_translate("Dialog", "author: Alopex Cheung"))
        self.contacLabel.setText(
            "contact: <a href=\"mailto:alopex4@163.com\">alopex4@163.com</a> \n"
            "")
        self.versionLabel.setText(_translate("Dialog", "version: 0.12"))


class Ui_AuthorDialog(QtWidgets.QDialog, Ui_Dialog):
    def __init__(self, parent=None):
        super(QtWidgets.QDialog, self).__init__(parent)
        self.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('../spruce.ico'))
        self.setWindowTitle('current state')
        self.setFixedSize(272, 440)
        self.iconLabel.clear()
        author_icon = QtGui.QPixmap('../spruce.ico')
        self.iconLabel.setPixmap(author_icon)
        self.contacLabel.setText("<a href='http://www.google.com'>Welcome to google</a>")


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    author = Ui_AuthorDialog()
    author.show()
    sys.exit(app.exec_())