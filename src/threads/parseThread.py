#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore

from src.capturePkt.cookedPacket import CookedPacket


class ParseThread(QtCore.QThread):
    cookedSignal = QtCore.pyqtSignal(object)

    def __init__(self, packet):
        super().__init__()
        self.packet = packet
        self.startFlag = True

    def __del__(self):
        self.quit()
        self.wait()

    def stop(self):
        self.startFlag = False

    def run(self):
        if self.startFlag:
            cookPacket = CookedPacket(self.packet)
            self.cookedSignal.emit(cookPacket)
