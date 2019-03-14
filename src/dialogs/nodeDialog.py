# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'node.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(262, 284)
        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.nodeIpLineEdit = QtWidgets.QLineEdit(Dialog)
        self.nodeIpLineEdit.setObjectName("nodeIpLineEdit")
        self.gridLayout.addWidget(self.nodeIpLineEdit, 1, 1, 1, 2)
        self.nodeMacIconLabel = QtWidgets.QLabel(Dialog)
        self.nodeMacIconLabel.setObjectName("nodeMacIconLabel")
        self.gridLayout.addWidget(self.nodeMacIconLabel, 3, 0, 1, 1)
        self.nodeMacLineEdit = QtWidgets.QLineEdit(Dialog)
        self.nodeMacLineEdit.setObjectName("nodeMacLineEdit")
        self.gridLayout.addWidget(self.nodeMacLineEdit, 3, 1, 1, 2)
        self.nodeVendorIconLabel = QtWidgets.QLabel(Dialog)
        self.nodeVendorIconLabel.setObjectName("nodeVendorIconLabel")
        self.gridLayout.addWidget(self.nodeVendorIconLabel, 5, 0, 1, 1)
        self.nodeMacTextLabel = QtWidgets.QLabel(Dialog)
        self.nodeMacTextLabel.setObjectName("nodeMacTextLabel")
        self.gridLayout.addWidget(self.nodeMacTextLabel, 2, 0, 1, 2)
        self.nodeVendorTextLabel = QtWidgets.QLabel(Dialog)
        self.nodeVendorTextLabel.setObjectName("nodeVendorTextLabel")
        self.gridLayout.addWidget(self.nodeVendorTextLabel, 4, 0, 1, 2)
        self.nodeIpTextLabel = QtWidgets.QLabel(Dialog)
        self.nodeIpTextLabel.setObjectName("nodeIpTextLabel")
        self.gridLayout.addWidget(self.nodeIpTextLabel, 0, 0, 1, 2)
        self.nodeVendorLineEdit = QtWidgets.QLineEdit(Dialog)
        self.nodeVendorLineEdit.setObjectName("nodeVendorLineEdit")
        self.gridLayout.addWidget(self.nodeVendorLineEdit, 5, 1, 1, 2)
        self.nodeTypeIconLabel = QtWidgets.QLabel(Dialog)
        self.nodeTypeIconLabel.setObjectName("nodeTypeIconLabel")
        self.gridLayout.addWidget(self.nodeTypeIconLabel, 7, 0, 1, 1)
        self.nodeTypeLineEdit = QtWidgets.QLineEdit(Dialog)
        self.nodeTypeLineEdit.setObjectName("nodeTypeLineEdit")
        self.gridLayout.addWidget(self.nodeTypeLineEdit, 7, 1, 1, 2)
        self.nodeIpIconLabel = QtWidgets.QLabel(Dialog)
        self.nodeIpIconLabel.setObjectName("nodeIpIconLabel")
        self.gridLayout.addWidget(self.nodeIpIconLabel, 1, 0, 1, 1)
        self.nodeTypeTextLabel = QtWidgets.QLabel(Dialog)
        self.nodeTypeTextLabel.setObjectName("nodeTypeTextLabel")
        self.gridLayout.addWidget(self.nodeTypeTextLabel, 6, 0, 1, 2)
        self.nodeOkButton = QtWidgets.QPushButton(Dialog)
        self.nodeOkButton.setObjectName("nodeOkButton")
        self.gridLayout.addWidget(self.nodeOkButton, 8, 2, 1, 1)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.nodeMacIconLabel.setText(_translate("Dialog", "TextLabel"))
        self.nodeVendorIconLabel.setText(_translate("Dialog", "TextLabel"))
        self.nodeMacTextLabel.setText(_translate("Dialog", "Mac address:"))
        self.nodeVendorTextLabel.setText(_translate("Dialog", "Vendor:"))
        self.nodeIpTextLabel.setText(_translate("Dialog", "Ip address:"))
        self.nodeTypeIconLabel.setText(_translate("Dialog", "TextLabel"))
        self.nodeIpIconLabel.setText(_translate("Dialog", "TextLabel"))
        self.nodeTypeTextLabel.setText(_translate("Dialog", "Node type:"))
        self.nodeOkButton.setText(_translate("Dialog", "ok"))
