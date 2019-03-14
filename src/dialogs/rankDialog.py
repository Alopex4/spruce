# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'rank.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

import sys

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(247, 147)
        self.formLayout = QtWidgets.QFormLayout(Form)
        self.formLayout.setObjectName("formLayout")
        self.rootLabel = QtWidgets.QLabel(Form)
        self.rootLabel.setObjectName("rootLabel")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole,
                                  self.rootLabel)
        self.rootStateLabel = QtWidgets.QLabel(Form)
        self.rootStateLabel.setObjectName("rootStateLabel")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.FieldRole,
                                  self.rootStateLabel)
        self.netLabel = QtWidgets.QLabel(Form)
        self.netLabel.setObjectName("netLabel")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole,
                                  self.netLabel)
        self.netStateLabel = QtWidgets.QLabel(Form)
        self.netStateLabel.setObjectName("netStateLabel")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole,
                                  self.netStateLabel)
        self.routingLabel = QtWidgets.QLabel(Form)
        self.routingLabel.setObjectName("routingLabel")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole,
                                  self.routingLabel)
        self.routingStateLabel = QtWidgets.QLabel(Form)
        self.routingStateLabel.setObjectName("routingStateLabel")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole,
                                  self.routingStateLabel)
        self.dumpLabel = QtWidgets.QLabel(Form)
        self.dumpLabel.setObjectName("dumpLabel")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.LabelRole,
                                  self.dumpLabel)
        self.dumpStateLabel = QtWidgets.QLabel(Form)
        self.dumpStateLabel.setObjectName("dumpStateLabel")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.FieldRole,
                                  self.dumpStateLabel)

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.rootLabel.setText(_translate("Form", "root privilege"))
        self.rootStateLabel.setText(_translate("Form", "TextLabel"))
        self.netLabel.setText(_translate("Form", "network status"))
        self.netStateLabel.setText(_translate("Form", "TextLabel"))
        self.routingLabel.setText(_translate("Form", "ip routing"))
        self.routingStateLabel.setText(_translate("Form", "TextLabel"))
        self.dumpLabel.setText(_translate("Form", "tcpdump install"))
        self.dumpStateLabel.setText(_translate("Form", "TextLabel"))


class Ui_RankDialog(QtWidgets.QDialog, Ui_Form):
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


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    spruce = Ui_RankDialog()
    spruce.show()
    sys.exit(app.exec_())
