#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from PyQt5 import QtCore


# class QueryThread(QtCore.QObject):
class QueryThread(QtCore.QThread):
    finishSignal = QtCore.pyqtSignal(bool)
    jsonSignal = QtCore.pyqtSignal(str)
    infoSignal = QtCore.pyqtSignal(str, str)

    def __init__(self, ip, token='80977e50c0ef36'):
        super().__init__()
        self.token = token
        self.queryIP = ip

    def __del__(self):
        # Destroyed while thread is still running
        # Solution https://blog.csdn.net/suli_fly/article/details/21627535
        self.quit()
        # self.wait()

    def run(self):
        self.finishSignal.emit(False)
        url = 'http://ipinfo.io/{searchIP}?token={token}'.format(
            searchIP=self.queryIP, token=self.token)
        try:
            ipJSON = requests.get(url, timeout=1.0).text
        except (requests.ConnectionError, requests.exceptions.ReadTimeout):
            self.infoSignal.emit('Search Info',
                                 'Make sure your network is stable')
        else:
            self.jsonSignal.emit(ipJSON)
        finally:
            self.finishSignal.emit(True)
