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
        self.temLayout = QtWidgets.QVBoxLayout()
        self.resize(400, 500)
        self.tempTextBrowser = QtWidgets.QTextBrowser()
        self.tempTextBrowser.setReadOnly(True)
        self.temLayout.addWidget(self.tempTextBrowser)
        self.tempTextBrowser.setOpenExternalLinks(True)
        demoText = '<p>HTTP uses a server-client model.  A <a href="https://techterms.com/definition/client">client</a>, for example, may be a home computer, laptop, or mobile device.  The HTTP <a href="/definition/server">server</a> is typically a <a href="/definition/webhost">web host</a> running web server software, such as <a href="/definition/apache">Apache</a> or <a href="/definition/iis">IIS</a>.  When you access a website, your <a href="/definition/web_browser">browser</a> sends a request to the corresponding web server and it responds with an HTTP status code.  If the <a href="/definition/url">URL</a> is valid and the connection is granted, the server will send your browser the webpage and related files.</p>'
        self.tempTextBrowser.setText(demoText)

        self.setLayout(self.temLayout)


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    demo = MyDemo()
    demo.show()
    sys.exit(app.exec_())
