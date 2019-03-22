#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from PyQt5 import QtCore


class OpenThread(QtCore.QThread):
    readSignal = QtCore.pyqtSignal(int, int, int, bytes)

    def __init__(self, fileName, fileSize):
        super().__init__()
        self.file = fileName
        self.fileSize = fileSize
        self.index = 0

    def run(self):
        index = 0
        with open(self.file, 'rb') as pcapFile:
            # Remove the header info
            _ = pcapFile.read(24)
            while pcapFile.tell() != self.fileSize:
                index += 1
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                    '@I I I I', pcapFile.read(16))
                packet = pcapFile.read(incl_len)
                self.readSignal.emit(ts_sec, ts_usec, index, packet)
