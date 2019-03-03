#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import struct


class UnpackFile:
    CST_time_zone = 8 * 60 * 60

    def __init__(self, file_name='demo.pcap'):
        self.name = file_name
        self.file = open(self.name, 'rb')
        self.file_header = self._get_file_header()
        self.is_pacap = self._is_pacap_file()
        self.packets = []
        self.size = os.path.getsize(self.name)

    def _get_file_header(self):
        header = self.file.read(24)
        magic, majv, minv, zone, signi, snaplen, network = struct.unpack(
            '@i h h i I I I', header)
        file_header = (magic, majv, minv, zone, signi, snaplen, network)
        return file_header

    def _is_pacap_file(self):
        magic, majv, minv = self.file_header[0:3]
        if magic == 0xa1b2c3d4 and majv == 0x4 and minv == 0x2:
            return True
        return False

    def unpackaget(self):
        ts_sec, ts_usec = struct.unpack('@I I ', self.file.read(8))
        date_time = float(
            str(ts_sec) + '.' + str(ts_usec)) + unpack.CST_time_zone
        date_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(date_time))
        incl_len, orig_len = struct.unpack('@I I', self.file.read(8))
        row_data = self.file.read(incl_len)
        item = (date_time, incl_len, orig_len, row_data)
        self.packets.append(item)

    def unpackaget_all(self):
        while self.file.tell() != self.size:
            self.unpackaget()

    def __len__(self):
        return len(self.packets)

    def show_packaget(self, index):
        print(self.packets[index])


if __name__ == '__main__':
    unpack = UnpackFile('capture.pcap')
    unpack.unpackaget_all()
    package_data = unpack.packets
    for i in package_data:
        print(i[0:2])
    print(len(unpack))
