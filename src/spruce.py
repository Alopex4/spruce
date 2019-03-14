#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from PyQt5 import QtWidgets

# from mainWindow import Ui_MainWindow
# from shineMainWindow import ShineMainWindow
# from brightMainWindow import BrightMainWindow
from windows.brightMainWindow import BrightMainWindow


class Spruce(BrightMainWindow):
    def __init__(self):
        super().__init__()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    spruce = Spruce()
    spruce.show()
    sys.exit(app.exec_())
