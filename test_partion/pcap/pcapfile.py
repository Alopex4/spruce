#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import struct


class PcapFile:
    def __init__(self, file_name='capture.pcap'):
        self.global_header = self._global_header()
        self.pcap_file = open(file_name, 'wb')
        self._write_meta()

    def _global_header(self):
        # Define the global header information
        header = struct.pack("@I H H i I I I", 0xa1b2c3d4, 0x2, 0x4, 0x0, 0x0,
                             0xffff, 0x1)
        return header

    def _package_header(self, package):
        # Define every package header info
        ts_sec, ts_usec = (int(ts.ljust(6, '0')) if len(ts) < 6 else int(ts)
                           for ts in str(round(time.time(), 6)).split('.'))
        # print(ts_sec, ts_usec)
        incl_len = len(package)
        orig_len = incl_len
        header = struct.pack("@I I I I", ts_sec, ts_usec, incl_len, orig_len)
        return header

    def _write_meta(self):
        self.pcap_file.write(self.global_header)

    def write_package(self, data):
        package_header = self._package_header(data)
        self.pcap_file.write(package_header)
        self.pcap_file.write(data)

    def write_finish(self):
        self.pcap_file.close()


class Package:
    def __init__(self):
        self.conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(3))
        self.buffer = 65535

    def capture_package(self, ifac):
        while True:
            data, addr = self.conn.recvfrom(self.buffer)
            if addr[0] != ifac:
                continue
            else:
                return data


if __name__ == '__main__':
    pcap = PcapFile()
    package = Package()

    for i in range(500):
        pcap.write_package(package.capture_package('wlp5s0'))

    pcap.write_finish()
