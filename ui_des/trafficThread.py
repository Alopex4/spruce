#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import psutil

from PyQt5 import QtCore


class TrafficThread(QtCore.QThread):
    speedSignal = QtCore.pyqtSignal(tuple, tuple)

    def __init__(self, inetName):
        self.goOn = True
        self.nicName = inetName
        super().__init__()

    def __del__(self):
        self.goOn = False
        self.quit()
        self.wait()

    def run(self):
        upload = 0.00
        download = 0.00
        t0 = time.time()
        prevUpDownDatas, prevSentRecv = self.getTrafficInfo(self.nicName)

        while self.goOn:
            currUpDownDatas, currSentRev = self.getTrafficInfo(self.nicName)
            t1 = time.time()

            ul, dl = [(curr - prev) / (t1 - t0) / 1024.0
                      for curr, prev in zip(currUpDownDatas, prevUpDownDatas)]
            t0 = time.time()
            upDown = (ul, dl)
            if dl > 0.1 or ul >= 0.1:
                time.sleep(0.75)
                self.speedSignal.emit(upDown, currSentRev)

            # self.uploadLabel.setText('upload:{:02f}KB |'.format(upload))
            # self.downloadLabel.setText('download:{:02f}KB |'.format(download))

    def getTrafficInfo(self, inetName):
        up, down, sent, recv, *_ = psutil.net_io_counters(
            pernic=True)[inetName]
        upDown = (up, down)
        sentRecv = (sent, recv)
        return upDown, sentRecv