#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore


class SearchThread(QtCore.QThread):
    searchSignal = QtCore.pyqtSignal(object)
    scrollSignal = QtCore.pyqtSignal()

    def __init__(self, package):
        super().__init__()
        self.package = package

    def run(self):
        for pkt in self.package:
            self.searchSignal.emit(pkt)
        self.scrollSignal.emit()
