#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from PyQt5 import QtWidgets


class MyDemo(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.initUi()

    def initUi(self):
        self.setWindowTitle('Demo')


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    demo = MyDemo()
    demo.show()
    sys.exit(app.exec_())
