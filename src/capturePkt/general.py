#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from prettytable import PrettyTable


def getMacAddr(macRaw):
    """  Get mac address via parameter mac raw """

    byte_str = map('{:02x}'.format, macRaw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


def getIdentifier(RawInfo):
    """  Get interface identifier """

    ident = getMacAddr(RawInfo)
    return ident


def getIpv4(addr):
    """ Get IPv4 address via parameter addr """

    return '.'.join(map(str, addr))


def getIpv6(addr):
    """ Get ipv6 address via parameter addr """

    byte_str = map('{:02x}'.format, addr)
    ipv6_raw = ''.join(byte_str).upper()
    ipv6_cook = [ipv6_raw[i:i + 4] for i in range(0, len(ipv6_raw), 4)]
    ipv6_cooked = ':'.join(ipv6_cook)
    # cut head and tail zero
    ipv6_addr = ipv6_cooked.replace('0000:', '0:').replace(':0000', ':0')
    ipv6_addr = ipv6_addr.replace(':000', ':').replace(':00', ':')
    ipv6_addr = re.sub(r'^0+', '', ipv6_addr, count=1)
    ipv6_addr = re.sub(r'(:0){2,}', ':', ipv6_addr, count=1)
    if ipv6_addr == ':':
        return '::'
    return ipv6_addr


def hexToASCII(packet, padding):
    chCodes = []
    oneLineChar = r'.{{{}}}'.format(padding)
    rawData = packet.hex()
    rawData = re.findall(r'.{2}', rawData)
    rawData.extend([''] * padding)
    for ch in rawData:
        if ch:
            chCode = int(ch, base=16)
            if chCode > 33 and chCode < 126:
                chCodes.append(chr(chCode))
            else:
                chCodes.append('·')
        else:
            chCodes.append(ch)
    data = ''.join(chCodes) + ' ' * padding
    data = '\n'.join(re.findall(oneLineChar, data))
    data = data.strip()
    return data


def formatAssistant(title, field, parse):
    """ Zip field and data together and return a foramt info"""
    formatTable = PrettyTable()
    columnName = ['fields', 'parses']
    formatTable.add_column(columnName[0], field)
    formatTable.add_column(columnName[1], parse)
    formatTable.align['fields'] = "l"
    formatTable.align['parses'] = "l"
    return formatTable.get_string(title=title)
