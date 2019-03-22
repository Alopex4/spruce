#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from PyQt5 import QtCore


class SaveThread(QtCore.QThread):
    def __init__(self, fileName, packets):
        super().__init__()
        self.file = fileName
        self.packets = packets

    def run(self):
        # https://wiki.wireshark.org/Development/LibpcapFileFormat
        # Header structure
        # typedef struct pcap_hdr_s {
        #         guint32 magic_number;   /* magic number */
        #         guint16 version_major;  /* major version number */
        #         guint16 version_minor;  /* minor version number */
        #         gint32  thiszone;       /* GMT to local correction */
        #         guint32 sigfigs;        /* accuracy of timestamps */
        #         guint32 snaplen;        /* max length of captured packets, in octets */
        #         guint32 network;        /* data link type */
        # } pcap_hdr_t;

        # Package structure
        # typedef struct pcaprec_hdr_s {
        #         guint32 ts_sec;         /* timestamp seconds */
        #         guint32 ts_usec;        /* timestamp microseconds */
        #         guint32 incl_len;       /* number of octets of packet saved in file */
        #         guint32 orig_len;       /* actual length of packet */
        # } pcaprec_hdr_t;

        with open(self.file, 'wb') as pcapFile:
            # Header information
            pcapFile.write(
                struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535,
                            1))

            # Package information
            for pkt in self.packets:
                pcapFile.write(
                    struct.pack('@ I I I I', pkt.sec, pkt.usec, pkt.pktLen,
                                pkt.pktLen))
                pcapFile.write(pkt.pktData)
