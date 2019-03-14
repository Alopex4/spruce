#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from binascii import hexlify
from ctypes import create_string_buffer, addressof
from socket import socket, AF_PACKET, SOCK_RAW, SOL_SOCKET, ntohs
from struct import pack

# A subset of Berkeley Packet Filter constants and macros, as defined in
# linux/filter.h.


def bpf_jump(code, jt, jf, k):
    print(pack('HBBI', code, jt, jf, k))
    return pack('HBBI', code, jt, jf, k)


cc = [[40, 0, 0, 12], [21, 0, 3, 2048], [48, 0, 0, 23], [21, 0, 1, 1],
      [6, 0, 0, 262144], [6, 0, 0, 0]]

filters_list = [
    pack('HBBI', *c) for c in cc
    # bpf_jump(*c) for c in cc

    # bpf_jump(40, 0, 0, 12),
    # bpf_jump(21, 0, 3, 2048),
    # bpf_jump(48, 0, 0, 23),
    # bpf_jump(21, 0, 1, 1),
    # bpf_jump(6, 0, 0, 262144),
    # bpf_jump(6, 0, 0, 0)

    # bpf_jump(0x28, 0, 0, 0x0000000c),
    # bpf_jump(0x15, 0, 3, 0x00000800),
    # bpf_jump(0x30, 0, 0, 0x00000017),
    # bpf_jump(0x15, 0, 1, 0x00000001),
    # bpf_jump(0x6, 0, 0, 0x00040000),
    # bpf_jump(0x6, 0, 0, 0x00000000),
]

# Create filters struct and fprog struct to be used by SO_ATTACH_FILTER, as
# defined in linux/filter.h.

filters = b''.join(filters_list)
b = create_string_buffer(filters)
mem_addr_of_filters = addressof(b)
fprog = pack('HL', len(filters_list), mem_addr_of_filters)

# As defined in asm/socket.h
SO_ATTACH_FILTER = 26

# Create listening socket with filters
s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003))
s.setsockopt(SOL_SOCKET, SO_ATTACH_FILTER, fprog)

# bind (device, 2048)
s.bind(('wlp5s0', 0x0800))

while True:
    try:
        data, addr = s.recvfrom(65565)
        print('got data from', addr, ':', hexlify(data))
    except KeyboardInterrupt:
        sys.exit()
