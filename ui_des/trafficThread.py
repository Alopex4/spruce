#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import psutil

from PyQt5 import QtCore


class TrafficThread(QtCore.QThread):
    trafficSignal = QtCore.pyqtSignal(float, float, int, int)

    def __init__(self, inetName):
        super().__init__()
        self.goOn = True
        self.nicName = inetName
        _, packets = self.getTrafficInfo(self.nicName)
        self.prevSent = packets[0]
        self.prevRecv = packets[1]

    def __del__(self):
        self.goOn = False
        self.quit()
        self.wait()

    def run(self):
        upload = 0.00
        download = 0.00
        sent = 0
        recv = 0

        self.trafficSignal.emit(upload, download, sent, recv)
        while True:
            t0 = time.time()
            prevUpDownDatas, _ = self.getTrafficInfo(self.nicName)
            self.sleep(1)
            currUpDownDatas, currSentRev = self.getTrafficInfo(self.nicName)
            t1 = time.time()

            upload, download = [
                (curr - prev) / (t1 - t0) / 1024.0
                for curr, prev in zip(currUpDownDatas, prevUpDownDatas)
            ]
            sent = currSentRev[0] - self.prevSent
            recv = currSentRev[1] - self.prevRecv

            if self.goOn:
                self.trafficSignal.emit(upload, download, sent, recv)
            else:
                break

    def getTrafficInfo(self, inetName):
        up, down, sent, recv, *_ = psutil.net_io_counters(
            pernic=True)[inetName]
        upDown = (up, down)
        sentRecv = (sent, recv)
        return upDown, sentRecv