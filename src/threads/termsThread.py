#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from PyQt5 import QtCore


# class QueryThread(QtCore.QObject):
class TermsThread(QtCore.QThread):
    finishSignal = QtCore.pyqtSignal(bool)
    htmlSignal = QtCore.pyqtSignal(str)
    infoSignal = QtCore.pyqtSignal(str, str)

    def __init__(self, term):
        super().__init__()
        self.term = term

    def __del__(self):
        # Destroyed while thread is still running
        # Solution https://blog.csdn.net/suli_fly/article/details/21627535
        self.quit()
        self.wait()

    def run(self):
        self.finishSignal.emit(False)
        url = 'https://techterms.com/definition/{}'.format(self.term)
        try:
            termDefine = requests.get(url, timeout=1.0).text
        except (requests.ConnectionError, requests.exceptions.ReadTimeout):
            self.infoSignal.emit('Term Info',
                                 'Make sure your network is stable')
        else:
            self.htmlSignal.emit(termDefine)
        finally:
            self.finishSignal.emit(True)
