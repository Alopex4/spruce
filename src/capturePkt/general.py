#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def getMacAddr(macRaw):
    """  Get mac address via parameter mac raw """

    byte_str = map('{:02x}'.format, macRaw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


def getIpv4(addr):
    """ Get IPv4 address via parameter addr """

    return '.'.join(map(str, addr))


def getIpv6(addr):
    """ Get ipv6 address via parameter addr """

    byte_str = map('{:04x}'.format, addr)
    ipv6_addr = ':'.join(byte_str).upper().replace('0000', '0')
    if ipv6_addr.replace('0:', '') == '0':
        return '::'
    return ipv6_addr
