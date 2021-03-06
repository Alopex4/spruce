# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.5.1
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(849, 729)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.horizontalLayout_8 = QtWidgets.QHBoxLayout(self.centralwidget)
        self.horizontalLayout_8.setObjectName("horizontalLayout_8")
        self.splitter = QtWidgets.QSplitter(self.centralwidget)
        self.splitter.setOrientation(QtCore.Qt.Vertical)
        self.splitter.setObjectName("splitter")
        self.conciseInfoTable = QtWidgets.QTableWidget(self.splitter)
        self.conciseInfoTable.setStyleSheet("outline:0;")
        self.conciseInfoTable.setShowGrid(False)
        self.conciseInfoTable.setGridStyle(QtCore.Qt.NoPen)
        self.conciseInfoTable.setObjectName("conciseInfoTable")
        self.conciseInfoTable.setColumnCount(7)
        self.conciseInfoTable.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.conciseInfoTable.setHorizontalHeaderItem(6, item)
        self.verboseInfoTab = QtWidgets.QTabWidget(self.splitter)
        self.verboseInfoTab.setObjectName("verboseInfoTab")
        self.linkTab = QtWidgets.QWidget()
        self.linkTab.setObjectName("linkTab")
        self.verticalLayout_7 = QtWidgets.QVBoxLayout(self.linkTab)
        self.verticalLayout_7.setObjectName("verticalLayout_7")
        self.linkTextEdit = QtWidgets.QPlainTextEdit(self.linkTab)
        self.linkTextEdit.setObjectName("linkTextEdit")
        self.verticalLayout_7.addWidget(self.linkTextEdit)
        self.verboseInfoTab.addTab(self.linkTab, "")
        self.interTab = QtWidgets.QWidget()
        self.interTab.setObjectName("interTab")
        self.verticalLayout_6 = QtWidgets.QVBoxLayout(self.interTab)
        self.verticalLayout_6.setObjectName("verticalLayout_6")
        self.interTextEdit = QtWidgets.QPlainTextEdit(self.interTab)
        self.interTextEdit.setObjectName("interTextEdit")
        self.verticalLayout_6.addWidget(self.interTextEdit)
        self.verboseInfoTab.addTab(self.interTab, "")
        self.transTab = QtWidgets.QWidget()
        self.transTab.setObjectName("transTab")
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.transTab)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.transTextEdit = QtWidgets.QPlainTextEdit(self.transTab)
        self.transTextEdit.setObjectName("transTextEdit")
        self.verticalLayout_5.addWidget(self.transTextEdit)
        self.verboseInfoTab.addTab(self.transTab, "")
        self.appTab = QtWidgets.QWidget()
        self.appTab.setObjectName("appTab")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.appTab)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.appTextEdit = QtWidgets.QPlainTextEdit(self.appTab)
        self.appTextEdit.setObjectName("appTextEdit")
        self.verticalLayout_4.addWidget(self.appTextEdit)
        self.verboseInfoTab.addTab(self.appTab, "")
        self.decodeInfoTab = QtWidgets.QTabWidget(self.splitter)
        self.decodeInfoTab.setObjectName("decodeInfoTab")
        self.rawTab = QtWidgets.QWidget()
        self.rawTab.setObjectName("rawTab")
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.rawTab)
        self.verticalLayout_8.setObjectName("verticalLayout_8")
        self.rawTextEdit = QtWidgets.QPlainTextEdit(self.rawTab)
        self.rawTextEdit.setObjectName("rawTextEdit")
        self.verticalLayout_8.addWidget(self.rawTextEdit)
        self.decodeInfoTab.addTab(self.rawTab, "")
        self.utfTab = QtWidgets.QWidget()
        self.utfTab.setObjectName("utfTab")
        self.verticalLayout_9 = QtWidgets.QVBoxLayout(self.utfTab)
        self.verticalLayout_9.setObjectName("verticalLayout_9")
        self.utfTextEdit = QtWidgets.QPlainTextEdit(self.utfTab)
        self.utfTextEdit.setObjectName("utfTextEdit")
        self.verticalLayout_9.addWidget(self.utfTextEdit)
        self.decodeInfoTab.addTab(self.utfTab, "")
        self.horizontalLayout_8.addWidget(self.splitter)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 849, 26))
        self.menubar.setObjectName("menubar")
        self.menu_File = QtWidgets.QMenu(self.menubar)
        self.menu_File.setObjectName("menu_File")
        self.menu_export = QtWidgets.QMenu(self.menu_File)
        self.menu_export.setObjectName("menu_export")
        self.menuNetwork_info = QtWidgets.QMenu(self.menu_export)
        self.menuNetwork_info.setObjectName("menuNetwork_info")
        self.menuLAN_info = QtWidgets.QMenu(self.menu_export)
        self.menuLAN_info.setObjectName("menuLAN_info")
        self.menuPackets_info = QtWidgets.QMenu(self.menu_export)
        self.menuPackets_info.setObjectName("menuPackets_info")
        self.menu_Capture = QtWidgets.QMenu(self.menubar)
        self.menu_Capture.setObjectName("menu_Capture")
        self.menu_Statistic = QtWidgets.QMenu(self.menubar)
        self.menu_Statistic.setObjectName("menu_Statistic")
        self.menu_protocol = QtWidgets.QMenu(self.menu_Statistic)
        self.menu_protocol.setObjectName("menu_protocol")
        self.menu_length = QtWidgets.QMenu(self.menu_Statistic)
        self.menu_length.setObjectName("menu_length")
        self.menu_flow = QtWidgets.QMenu(self.menu_Statistic)
        self.menu_flow.setObjectName("menu_flow")
        self.menu_Option = QtWidgets.QMenu(self.menubar)
        self.menu_Option.setObjectName("menu_Option")
        self.menu_About = QtWidgets.QMenu(self.menubar)
        self.menu_About.setObjectName("menu_About")
        self.menuView = QtWidgets.QMenu(self.menubar)
        self.menuView.setObjectName("menuView")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.controlDock = QtWidgets.QDockWidget(MainWindow)
        self.controlDock.setEnabled(True)
        self.controlDock.setFloating(False)
        self.controlDock.setObjectName("controlDock")
        self.controlDockContents = QtWidgets.QWidget()
        self.controlDockContents.setObjectName("controlDockContents")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(
            self.controlDockContents)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.controlTabManage = QtWidgets.QTabWidget(self.controlDockContents)
        self.controlTabManage.setTabBarAutoHide(False)
        self.controlTabManage.setObjectName("controlTabManage")
        self.networkTab = QtWidgets.QWidget()
        self.networkTab.setObjectName("networkTab")
        self.formLayout = QtWidgets.QFormLayout(self.networkTab)
        self.formLayout.setObjectName("formLayout")
        self.nameLabel = QtWidgets.QLabel(self.networkTab)
        self.nameLabel.setObjectName("nameLabel")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.LabelRole,
                                  self.nameLabel)
        self.nameLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.nameLineEdit.setObjectName("nameLineEdit")
        self.formLayout.setWidget(1, QtWidgets.QFormLayout.FieldRole,
                                  self.nameLineEdit)
        self.ipLabel = QtWidgets.QLabel(self.networkTab)
        self.ipLabel.setObjectName("ipLabel")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.LabelRole,
                                  self.ipLabel)
        self.ipLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.ipLineEdit.setObjectName("ipLineEdit")
        self.formLayout.setWidget(2, QtWidgets.QFormLayout.FieldRole,
                                  self.ipLineEdit)
        self.macLabel = QtWidgets.QLabel(self.networkTab)
        self.macLabel.setObjectName("macLabel")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.LabelRole,
                                  self.macLabel)
        self.macLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.macLineEdit.setObjectName("macLineEdit")
        self.formLayout.setWidget(3, QtWidgets.QFormLayout.FieldRole,
                                  self.macLineEdit)
        self.vendorLabel = QtWidgets.QLabel(self.networkTab)
        self.vendorLabel.setObjectName("vendorLabel")
        self.formLayout.setWidget(4, QtWidgets.QFormLayout.LabelRole,
                                  self.vendorLabel)
        self.vendorLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.vendorLineEdit.setObjectName("vendorLineEdit")
        self.formLayout.setWidget(4, QtWidgets.QFormLayout.FieldRole,
                                  self.vendorLineEdit)
        self.netmaskLabel = QtWidgets.QLabel(self.networkTab)
        self.netmaskLabel.setObjectName("netmaskLabel")
        self.formLayout.setWidget(5, QtWidgets.QFormLayout.LabelRole,
                                  self.netmaskLabel)
        self.netmaskLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.netmaskLineEdit.setObjectName("netmaskLineEdit")
        self.formLayout.setWidget(5, QtWidgets.QFormLayout.FieldRole,
                                  self.netmaskLineEdit)
        self.gwIpLabel = QtWidgets.QLabel(self.networkTab)
        self.gwIpLabel.setObjectName("gwIpLabel")
        self.formLayout.setWidget(7, QtWidgets.QFormLayout.LabelRole,
                                  self.gwIpLabel)
        self.gwVendorLabel = QtWidgets.QLabel(self.networkTab)
        self.gwVendorLabel.setObjectName("gwVendorLabel")
        self.formLayout.setWidget(10, QtWidgets.QFormLayout.LabelRole,
                                  self.gwVendorLabel)
        self.gwVendorLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.gwVendorLineEdit.setObjectName("gwVendorLineEdit")
        self.formLayout.setWidget(10, QtWidgets.QFormLayout.FieldRole,
                                  self.gwVendorLineEdit)
        self.refreshButton = QtWidgets.QPushButton(self.networkTab)
        self.refreshButton.setObjectName("refreshButton")
        self.formLayout.setWidget(13, QtWidgets.QFormLayout.FieldRole,
                                  self.refreshButton)
        self.localLabel = QtWidgets.QLabel(self.networkTab)
        self.localLabel.setObjectName("localLabel")
        self.formLayout.setWidget(0, QtWidgets.QFormLayout.LabelRole,
                                  self.localLabel)
        self.gwLabel = QtWidgets.QLabel(self.networkTab)
        self.gwLabel.setObjectName("gwLabel")
        self.formLayout.setWidget(6, QtWidgets.QFormLayout.LabelRole,
                                  self.gwLabel)
        self.gwMacLabel = QtWidgets.QLabel(self.networkTab)
        self.gwMacLabel.setObjectName("gwMacLabel")
        self.formLayout.setWidget(8, QtWidgets.QFormLayout.LabelRole,
                                  self.gwMacLabel)
        self.unlockButton = QtWidgets.QPushButton(self.networkTab)
        self.unlockButton.setObjectName("unlockButton")
        self.formLayout.setWidget(13, QtWidgets.QFormLayout.LabelRole,
                                  self.unlockButton)
        self.gwIpLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.gwIpLineEdit.setObjectName("gwIpLineEdit")
        self.formLayout.setWidget(7, QtWidgets.QFormLayout.FieldRole,
                                  self.gwIpLineEdit)
        self.gwMacLineEdit = QtWidgets.QLineEdit(self.networkTab)
        self.gwMacLineEdit.setObjectName("gwMacLineEdit")
        self.formLayout.setWidget(8, QtWidgets.QFormLayout.FieldRole,
                                  self.gwMacLineEdit)
        self.controlTabManage.addTab(self.networkTab, "")
        self.scanTab = QtWidgets.QWidget()
        self.scanTab.setObjectName("scanTab")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.scanTab)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.rangeLabel = QtWidgets.QLabel(self.scanTab)
        self.rangeLabel.setObjectName("rangeLabel")
        self.verticalLayout_3.addWidget(self.rangeLabel)
        self.rangeLineEdit = QtWidgets.QLineEdit(self.scanTab)
        self.rangeLineEdit.setObjectName("rangeLineEdit")
        self.verticalLayout_3.addWidget(self.rangeLineEdit)
        self.rangeButton = QtWidgets.QPushButton(self.scanTab)
        self.rangeButton.setObjectName("rangeButton")
        self.verticalLayout_3.addWidget(self.rangeButton)
        self.maskLabel = QtWidgets.QLabel(self.scanTab)
        self.maskLabel.setObjectName("maskLabel")
        self.verticalLayout_3.addWidget(self.maskLabel)
        self.maskLineEdit = QtWidgets.QLineEdit(self.scanTab)
        self.maskLineEdit.setObjectName("maskLineEdit")
        self.verticalLayout_3.addWidget(self.maskLineEdit)
        self.maskButton = QtWidgets.QPushButton(self.scanTab)
        self.maskButton.setObjectName("maskButton")
        self.verticalLayout_3.addWidget(self.maskButton)
        self.controlTabManage.addTab(self.scanTab, "")
        self.searchTab = QtWidgets.QWidget()
        self.searchTab.setObjectName("searchTab")
        self.formLayout_4 = QtWidgets.QFormLayout(self.searchTab)
        self.formLayout_4.setObjectName("formLayout_4")
        self.searchLabel = QtWidgets.QLabel(self.searchTab)
        self.searchLabel.setObjectName("searchLabel")
        self.formLayout_4.setWidget(0, QtWidgets.QFormLayout.LabelRole,
                                    self.searchLabel)
        self.searchLineEdit = QtWidgets.QLineEdit(self.searchTab)
        self.searchLineEdit.setObjectName("searchLineEdit")
        self.formLayout_4.setWidget(0, QtWidgets.QFormLayout.FieldRole,
                                    self.searchLineEdit)
        self.searchButton = QtWidgets.QPushButton(self.searchTab)
        self.searchButton.setObjectName("searchButton")
        self.formLayout_4.setWidget(1, QtWidgets.QFormLayout.FieldRole,
                                    self.searchButton)
        self.controlTabManage.addTab(self.searchTab, "")
        self.ipinfoTab = QtWidgets.QWidget()
        self.ipinfoTab.setObjectName("ipinfoTab")
        self.formLayout_3 = QtWidgets.QFormLayout(self.ipinfoTab)
        self.formLayout_3.setObjectName("formLayout_3")
        self.sipLabel = QtWidgets.QLabel(self.ipinfoTab)
        self.sipLabel.setObjectName("sipLabel")
        self.formLayout_3.setWidget(0, QtWidgets.QFormLayout.LabelRole,
                                    self.sipLabel)
        self.sipLineEdit = QtWidgets.QLineEdit(self.ipinfoTab)
        self.sipLineEdit.setObjectName("sipLineEdit")
        self.formLayout_3.setWidget(0, QtWidgets.QFormLayout.FieldRole,
                                    self.sipLineEdit)
        self.sipTextEdit = QtWidgets.QTextEdit(self.ipinfoTab)
        self.sipTextEdit.setObjectName("sipTextEdit")
        self.formLayout_3.setWidget(1, QtWidgets.QFormLayout.SpanningRole,
                                    self.sipTextEdit)
        self.sipButton = QtWidgets.QPushButton(self.ipinfoTab)
        self.sipButton.setObjectName("sipButton")
        self.formLayout_3.setWidget(2, QtWidgets.QFormLayout.LabelRole,
                                    self.sipButton)
        self.controlTabManage.addTab(self.ipinfoTab, "")
        self.termTab = QtWidgets.QWidget()
        self.termTab.setObjectName("termTab")
        self.gridLayout = QtWidgets.QGridLayout(self.termTab)
        self.gridLayout.setObjectName("gridLayout")
        self.termLabel = QtWidgets.QLabel(self.termTab)
        self.termLabel.setObjectName("termLabel")
        self.gridLayout.addWidget(self.termLabel, 0, 0, 1, 1)
        self.termLineEdit = QtWidgets.QLineEdit(self.termTab)
        self.termLineEdit.setObjectName("termLineEdit")
        self.gridLayout.addWidget(self.termLineEdit, 0, 1, 1, 1)
        self.termButton = QtWidgets.QPushButton(self.termTab)
        self.termButton.setObjectName("termButton")
        self.gridLayout.addWidget(self.termButton, 2, 0, 1, 2)
        self.termTextEdit = QtWidgets.QTextEdit(self.termTab)
        self.termTextEdit.setObjectName("termTextEdit")
        self.gridLayout.addWidget(self.termTextEdit, 1, 0, 1, 2)
        self.controlTabManage.addTab(self.termTab, "")
        self.horizontalLayout_2.addWidget(self.controlTabManage)
        self.controlDock.setWidget(self.controlDockContents)
        MainWindow.addDockWidget(QtCore.Qt.DockWidgetArea(2), self.controlDock)
        self.scanDock = QtWidgets.QDockWidget(MainWindow)
        self.scanDock.setObjectName("scanDock")
        self.scanDockContents = QtWidgets.QWidget()
        self.scanDockContents.setObjectName("scanDockContents")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.scanDockContents)
        self.verticalLayout.setObjectName("verticalLayout")
        self.nodeListWidget = QtWidgets.QListWidget(self.scanDockContents)
        self.nodeListWidget.setStyleSheet("outline:0;")
        self.nodeListWidget.setObjectName("nodeListWidget")
        self.verticalLayout.addWidget(self.nodeListWidget)
        self.scanProgressBar = QtWidgets.QProgressBar(self.scanDockContents)
        self.scanProgressBar.setProperty("value", 24)
        self.scanProgressBar.setObjectName("scanProgressBar")
        self.verticalLayout.addWidget(self.scanProgressBar)
        self.analysisButton = QtWidgets.QPushButton(self.scanDockContents)
        self.analysisButton.setObjectName("analysisButton")
        self.verticalLayout.addWidget(self.analysisButton)
        self.stopButton = QtWidgets.QPushButton(self.scanDockContents)
        self.stopButton.setObjectName("stopButton")
        self.verticalLayout.addWidget(self.stopButton)
        self.scanDock.setWidget(self.scanDockContents)
        MainWindow.addDockWidget(QtCore.Qt.DockWidgetArea(2), self.scanDock)
        self.action_Save = QtWidgets.QAction(MainWindow)
        self.action_Save.setObjectName("action_Save")
        self.action_Open = QtWidgets.QAction(MainWindow)
        self.action_Open.setObjectName("action_Open")
        self.action_Export = QtWidgets.QAction(MainWindow)
        self.action_Export.setObjectName("action_Export")
        self.actionNetCSV = QtWidgets.QAction(MainWindow)
        self.actionNetCSV.setObjectName("actionNetCSV")
        self.actionNetJSON = QtWidgets.QAction(MainWindow)
        self.actionNetJSON.setObjectName("actionNetJSON")
        self.actionNetPlain = QtWidgets.QAction(MainWindow)
        self.actionNetPlain.setObjectName("actionNetPlain")
        self.actionLANCSV = QtWidgets.QAction(MainWindow)
        self.actionLANCSV.setObjectName("actionLANCSV")
        self.actionLANJSON = QtWidgets.QAction(MainWindow)
        self.actionLANJSON.setObjectName("actionLANJSON")
        self.actionLANPlain = QtWidgets.QAction(MainWindow)
        self.actionLANPlain.setObjectName("actionLANPlain")
        self.actionPktCSV = QtWidgets.QAction(MainWindow)
        self.actionPktCSV.setObjectName("actionPktCSV")
        self.actionPktJSON = QtWidgets.QAction(MainWindow)
        self.actionPktJSON.setObjectName("actionPktJSON")
        self.actionPktPlain = QtWidgets.QAction(MainWindow)
        self.actionPktPlain.setObjectName("actionPktPlain")
        self.action_Start = QtWidgets.QAction(MainWindow)
        self.action_Start.setObjectName("action_Start")
        self.actionSto_p = QtWidgets.QAction(MainWindow)
        self.actionSto_p.setObjectName("actionSto_p")
        self.action_restart = QtWidgets.QAction(MainWindow)
        self.action_restart.setObjectName("action_restart")
        self.action_Addr = QtWidgets.QAction(MainWindow)
        self.action_Addr.setObjectName("action_Addr")
        self.action_Layer = QtWidgets.QAction(MainWindow)
        self.action_Layer.setObjectName("action_Layer")
        self.action_Type = QtWidgets.QAction(MainWindow)
        self.action_Type.setObjectName("action_Type")
        self.action_PktLen = QtWidgets.QAction(MainWindow)
        self.action_PktLen.setObjectName("action_PktLen")
        self.action_UDPPktLen = QtWidgets.QAction(MainWindow)
        self.action_UDPPktLen.setObjectName("action_UDPPktLen")
        self.action_TCPPktLen = QtWidgets.QAction(MainWindow)
        self.action_TCPPktLen.setObjectName("action_TCPPktLen")
        self.action_IOflow = QtWidgets.QAction(MainWindow)
        self.action_IOflow.setObjectName("action_IOflow")
        self.action_Speed = QtWidgets.QAction(MainWindow)
        self.action_Speed.setObjectName("action_Speed")
        self.action_Gobal = QtWidgets.QAction(MainWindow)
        self.action_Gobal.setObjectName("action_Gobal")
        self.action_Stop = QtWidgets.QAction(MainWindow)
        self.action_Stop.setObjectName("action_Stop")
        self.action_Restart = QtWidgets.QAction(MainWindow)
        self.action_Restart.setObjectName("action_Restart")
        self.action_Help = QtWidgets.QAction(MainWindow)
        self.action_Help.setObjectName("action_Help")
        self.action_Author = QtWidgets.QAction(MainWindow)
        self.action_Author.setObjectName("action_Author")
        self.action_close = QtWidgets.QAction(MainWindow)
        self.action_close.setObjectName("action_close")
        self.action_rank = QtWidgets.QAction(MainWindow)
        self.action_rank.setObjectName("action_rank")
        self.action_Rank = QtWidgets.QAction(MainWindow)
        self.action_Rank.setObjectName("action_Rank")
        self.action_Filter = QtWidgets.QAction(MainWindow)
        self.action_Filter.setObjectName("action_Filter")
        self.action_RefreshRank = QtWidgets.QAction(MainWindow)
        self.action_RefreshRank.setObjectName("action_RefreshRank")
        self.action_CtrlPan = QtWidgets.QAction(MainWindow)
        self.action_CtrlPan.setObjectName("action_CtrlPan")
        self.action_ScanPan = QtWidgets.QAction(MainWindow)
        self.action_ScanPan.setObjectName("action_ScanPan")
        self.menuNetwork_info.addAction(self.actionNetCSV)
        self.menuNetwork_info.addAction(self.actionNetJSON)
        self.menuNetwork_info.addAction(self.actionNetPlain)
        self.menuLAN_info.addAction(self.actionLANCSV)
        self.menuLAN_info.addAction(self.actionLANJSON)
        self.menuLAN_info.addAction(self.actionLANPlain)
        self.menuPackets_info.addAction(self.actionPktCSV)
        self.menuPackets_info.addAction(self.actionPktJSON)
        self.menuPackets_info.addAction(self.actionPktPlain)
        self.menu_export.addAction(self.menuNetwork_info.menuAction())
        self.menu_export.addAction(self.menuLAN_info.menuAction())
        self.menu_export.addAction(self.menuPackets_info.menuAction())
        self.menu_File.addAction(self.action_Save)
        self.menu_File.addAction(self.action_Open)
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.menu_export.menuAction())
        self.menu_File.addSeparator()
        self.menu_File.addAction(self.action_close)
        self.menu_Capture.addAction(self.action_Start)
        self.menu_Capture.addSeparator()
        self.menu_Capture.addAction(self.action_Stop)
        self.menu_Capture.addSeparator()
        self.menu_Capture.addAction(self.action_Restart)
        self.menu_protocol.addAction(self.action_Addr)
        self.menu_protocol.addAction(self.action_Layer)
        self.menu_protocol.addAction(self.action_Type)
        self.menu_length.addAction(self.action_PktLen)
        self.menu_length.addAction(self.action_UDPPktLen)
        self.menu_length.addAction(self.action_TCPPktLen)
        self.menu_flow.addAction(self.action_IOflow)
        self.menu_flow.addAction(self.action_Speed)
        self.menu_flow.addAction(self.action_Gobal)
        self.menu_Statistic.addAction(self.menu_flow.menuAction())
        self.menu_Statistic.addAction(self.menu_protocol.menuAction())
        self.menu_Statistic.addAction(self.menu_length.menuAction())
        self.menu_Option.addSeparator()
        self.menu_Option.addAction(self.action_Filter)
        self.menu_Option.addSeparator()
        self.menu_Option.addAction(self.action_RefreshRank)
        self.menu_About.addAction(self.action_Help)
        self.menu_About.addSeparator()
        self.menu_About.addAction(self.action_Author)
        self.menu_About.addSeparator()
        self.menu_About.addAction(self.action_Rank)
        self.menuView.addAction(self.action_CtrlPan)
        self.menuView.addAction(self.action_ScanPan)
        self.menubar.addAction(self.menu_File.menuAction())
        self.menubar.addAction(self.menuView.menuAction())
        self.menubar.addAction(self.menu_Capture.menuAction())
        self.menubar.addAction(self.menu_Statistic.menuAction())
        self.menubar.addAction(self.menu_Option.menuAction())
        self.menubar.addAction(self.menu_About.menuAction())

        self.retranslateUi(MainWindow)
        self.verboseInfoTab.setCurrentIndex(0)
        self.decodeInfoTab.setCurrentIndex(0)
        self.controlTabManage.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        item = self.conciseInfoTable.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "No."))
        item = self.conciseInfoTable.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Time"))
        item = self.conciseInfoTable.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Source"))
        item = self.conciseInfoTable.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.conciseInfoTable.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.conciseInfoTable.horizontalHeaderItem(5)
        item.setText(_translate("MainWindow", "Length"))
        item = self.conciseInfoTable.horizontalHeaderItem(6)
        item.setText(_translate("MainWindow", "Stack"))
        self.verboseInfoTab.setTabText(
            self.verboseInfoTab.indexOf(self.linkTab),
            _translate("MainWindow", "link"))
        self.verboseInfoTab.setTabText(
            self.verboseInfoTab.indexOf(self.interTab),
            _translate("MainWindow", "internet"))
        self.verboseInfoTab.setTabText(
            self.verboseInfoTab.indexOf(self.transTab),
            _translate("MainWindow", "transport / extend"))
        self.verboseInfoTab.setTabText(self.verboseInfoTab.indexOf(self.appTab),
                                       _translate("MainWindow", "application"))
        self.decodeInfoTab.setTabText(self.decodeInfoTab.indexOf(self.rawTab),
                                      _translate("MainWindow", "hex decode"))
        self.decodeInfoTab.setTabText(self.decodeInfoTab.indexOf(self.utfTab),
                                      _translate("MainWindow", "utf decode"))
        self.menu_File.setTitle(_translate("MainWindow", "&File"))
        self.menu_export.setTitle(_translate("MainWindow", "&export"))
        self.menuNetwork_info.setTitle(
            _translate("MainWindow", "&network info"))
        self.menuLAN_info.setTitle(_translate("MainWindow", "&LAN info"))
        self.menuPackets_info.setTitle(
            _translate("MainWindow", "&packets info"))
        self.menu_Capture.setTitle(_translate("MainWindow", "&Capture"))
        self.menu_Statistic.setTitle(_translate("MainWindow", "&Statistic"))
        self.menu_protocol.setTitle(_translate("MainWindow", "&protocol"))
        self.menu_length.setTitle(_translate("MainWindow", "&length"))
        self.menu_flow.setTitle(_translate("MainWindow", "&flow"))
        self.menu_Option.setTitle(_translate("MainWindow", "&Option"))
        self.menu_About.setTitle(_translate("MainWindow", "&About"))
        self.menuView.setTitle(_translate("MainWindow", "&View"))
        self.controlDock.setWindowTitle(
            _translate("MainWindow", "Control Panel"))
        self.nameLabel.setText(_translate("MainWindow", "Name"))
        self.ipLabel.setText(_translate("MainWindow", "IP"))
        self.macLabel.setText(_translate("MainWindow", "Mac"))
        self.vendorLabel.setText(_translate("MainWindow", "Vendor"))
        self.netmaskLabel.setText(_translate("MainWindow", "Netmask"))
        self.gwIpLabel.setText(_translate("MainWindow", "IP"))
        self.gwVendorLabel.setText(_translate("MainWindow", "Vendor"))
        self.refreshButton.setText(_translate("MainWindow", "refresh"))
        self.localLabel.setText(_translate("MainWindow", ">>> Local"))
        self.gwLabel.setText(_translate("MainWindow", ">>> Gateway"))
        self.gwMacLabel.setText(_translate("MainWindow", "Mac"))
        self.unlockButton.setText(_translate("MainWindow", "unlock"))
        self.controlTabManage.setTabText(
            self.controlTabManage.indexOf(self.networkTab),
            _translate("MainWindow", "network"))
        self.rangeLabel.setText(_translate("MainWindow", "Range"))
        self.rangeButton.setText(_translate("MainWindow", "range scan"))
        self.maskLabel.setText(_translate("MainWindow", "Mask"))
        self.maskButton.setText(_translate("MainWindow", "mask scan"))
        self.controlTabManage.setTabText(
            self.controlTabManage.indexOf(self.scanTab),
            _translate("MainWindow", "scan"))
        self.searchLabel.setText(_translate("MainWindow", "Search"))
        self.searchButton.setText(_translate("MainWindow", "search"))
        self.controlTabManage.setTabText(
            self.controlTabManage.indexOf(self.searchTab),
            _translate("MainWindow", "search"))
        self.sipLabel.setText(_translate("MainWindow", "Query IP"))
        self.sipButton.setText(_translate("MainWindow", "query"))
        self.controlTabManage.setTabText(
            self.controlTabManage.indexOf(self.ipinfoTab),
            _translate("MainWindow", "query"))
        self.termLabel.setText(_translate("MainWindow", "Query Term"))
        self.termButton.setText(_translate("MainWindow", "query"))
        self.controlTabManage.setTabText(
            self.controlTabManage.indexOf(self.termTab),
            _translate("MainWindow", "term"))
        self.scanDock.setWindowTitle(_translate("MainWindow", "Scan Panel"))
        self.analysisButton.setText(_translate("MainWindow", "analysis"))
        self.stopButton.setText(_translate("MainWindow", "stop"))
        self.action_Save.setText(_translate("MainWindow", "&save"))
        self.action_Open.setText(_translate("MainWindow", "&open"))
        self.action_Export.setText(_translate("MainWindow", "&Export"))
        self.actionNetCSV.setText(_translate("MainWindow", "&CSV"))
        self.actionNetJSON.setText(_translate("MainWindow", "&JSON"))
        self.actionNetPlain.setText(_translate("MainWindow", "&plain text"))
        self.actionLANCSV.setText(_translate("MainWindow", "CSV"))
        self.actionLANJSON.setText(_translate("MainWindow", "JSON"))
        self.actionLANPlain.setText(_translate("MainWindow", "plain text"))
        self.actionPktCSV.setText(_translate("MainWindow", "CSV"))
        self.actionPktJSON.setText(_translate("MainWindow", "JSON"))
        self.actionPktPlain.setText(_translate("MainWindow", "plain text"))
        self.action_Start.setText(_translate("MainWindow", "&start"))
        self.actionSto_p.setText(_translate("MainWindow", "sto&p"))
        self.action_restart.setText(_translate("MainWindow", "&restart"))
        self.action_Addr.setText(_translate("MainWindow", "&adddress"))
        self.action_Layer.setText(_translate("MainWindow", "&layer"))
        self.action_Type.setText(_translate("MainWindow", "&type"))
        self.action_PktLen.setText(_translate("MainWindow", "&all"))
        self.action_UDPPktLen.setText(_translate("MainWindow", "&UDP"))
        self.action_TCPPktLen.setText(_translate("MainWindow", "&TCP"))
        self.action_IOflow.setText(_translate("MainWindow", "&I/O package"))
        self.action_Speed.setText(_translate("MainWindow", "&Up/Down speed"))
        self.action_Gobal.setText(_translate("MainWindow", "&global"))
        self.action_Stop.setText(_translate("MainWindow", "sto&p"))
        self.action_Restart.setText(_translate("MainWindow", "&restart"))
        self.action_Help.setText(_translate("MainWindow", "&help"))
        self.action_Author.setText(_translate("MainWindow", "&author"))
        self.action_close.setText(_translate("MainWindow", "&close"))
        self.action_close.setShortcut(_translate("MainWindow", "Ctrl+Q"))
        self.action_rank.setText(_translate("MainWindow", "&rank"))
        self.action_Rank.setText(_translate("MainWindow", "&rank"))
        self.action_Filter.setText(_translate("MainWindow", "&filter"))
        self.action_RefreshRank.setText(
            _translate("MainWindow", "&refresh rank"))
        self.action_CtrlPan.setText(_translate("MainWindow", "&Control Panel"))
        self.action_ScanPan.setText(_translate("MainWindow", "Scan Panel"))
