#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from PyQt5 import QtCore


class QueryThread(QtCore.QThread):
    finishSignal = QtCore.pyqtSignal(bool)
    jsonSignal = QtCore.pyqtSignal(str)
    infoSignal = QtCore.pyqtSignal(str, str)

    # def __init__(self, ip, token='80977e50c0ef36'):
    #     super().__init__()
    #     self.token = token
    #     self.queryIP = ip

    def __init__(self, ip):
        super().__init__()
        if not ip:
            ip = self._getLocalIP(url='http://ipv4.icanhazip.com/')
        self.queryIP = ip.strip()

    def __del__(self):
        # Destroyed while thread is still running
        # Solution https://blog.csdn.net/suli_fly/article/details/21627535
        self.quit()
        # self.wait()

    def _getLocalIP(self, url):
        result = '0.0.0.0'
        try:
            result = requests.get(url, timeout=1.0).text
        except requests.exceptions.RequestException:
            self.infoSignal.emit('Search Info',
                                 'Make sure your network is stable')
        finally:
            return result

    def run(self):
        self.finishSignal.emit(False)
        # url = 'http://ipinfo.io/{searchIP}?token={token}'.format(
        #     searchIP=self.queryIP, token=self.token)
        url = 'http://ip-api.com/json/{searchIP}'.format(searchIP=self.queryIP)
        try:
            ipJSON = requests.get(url, timeout=1.0).text
        except requests.exceptions.RequestException:
            self.infoSignal.emit('Search Info',
                                 'Make sure your network is stable')
        else:
            self.jsonSignal.emit(ipJSON)
        finally:
            self.finishSignal.emit(True)
