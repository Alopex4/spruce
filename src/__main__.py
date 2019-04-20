#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from PyQt5 import QtGui
from PyQt5 import QtCore
from PyQt5 import QtWidgets

# from mainWindow import Ui_MainWindow
# from shineMainWindow import ShineMainWindow
# from brightMainWindow import BrightMainWindow
from src.windows.brightMainWindow import BrightMainWindow


class Spruce(BrightMainWindow):
    def __init__(self):
        super().__init__()


def main():
    app = QtWidgets.QApplication(sys.argv)
    iconLoc = '{}/{}'.format(Spruce.iconDir, 'spruce.png')
    splash = QtWidgets.QSplashScreen(QtGui.QPixmap(iconLoc))
    statusFont = QtGui.QFont()
    statusFont.setBold(True)
    statusFont.setPointSize(16)
    splash.setFont(statusFont)
    splash.showMessage('Loading ... ...',
                       QtCore.Qt.AlignCenter | QtCore.Qt.AlignBottom,
                       QtCore.Qt.white)
    spruce = Spruce()
    app.processEvents()
    splash.show()
    QtCore.QTimer.singleShot(2500, splash.close)
    QtCore.QTimer.singleShot(2500, spruce.show)
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
