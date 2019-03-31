#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import socket
import struct
from binascii import hexlify
from ctypes import create_string_buffer, addressof

from PyQt5 import QtCore


class CaptureThread(QtCore.QThread):
    # tsSec, tsUsec, index, binaryPacket
    packetSignal = QtCore.pyqtSignal(int, int, int, bytes)

    def __init__(self, inetName, marcos):
        super().__init__()

        self.device = inetName
        self.marcos = marcos
        self.startFlag = True
        self.index = 0

    def __del__(self):
        self.quit()
        self.wait()

    def stop(self):
        self.startFlag = False

    def run(self):
        # Create raw socket to sniffer packets
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                          socket.ntohs(0x0003))

        # Create filters struct and fprog struct to be used by SO_ATTACH_FILTER, as
        macroFltList = [struct.pack('HBBI', *macro) for macro in self.marcos]
        stringBuffer = create_string_buffer(b''.join(macroFltList))
        memAddrOfMacroFlt = addressof(stringBuffer)
        fprog = struct.pack('HL', len(macroFltList), memAddrOfMacroFlt)

        # As defined in asm/socket.h
        SO_ATTACH_FILTER = 26

        s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
        # s.bind((self.device, 0x0800))

        while self.startFlag:
            packet, _ = s.recvfrom(65535)
            self.index += 1
            tsSec, tsUsec = (int(ts.ljust(6, '0')) if len(ts) < 6 else int(ts)
                             for ts in str(round(time.time(), 6)).split('.'))
            self.packetSignal.emit(tsSec, tsUsec, self.index, packet)
            # print('number ', self.index, 'got data from', addr, ':',
            #       hexlify(packet))
