#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import textwrap

TAB_1 = '\t -'
TAB_2 = '\t\t -'
TAB_3 = '\t\t\t -'
TAB_4 = '\t\t\t\t -'

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '


def main():
    """main program"""
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    # conn = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
    #                      socket.htons(0x0800))
    while True:
        data, data_addr = conn.recvfrom(65535)
        dest_mac, src_mac, ether_proto, data = ether_frame(data)
        print('\nEthernet Frame: ')
        print(TAB_1 + 'dest addr:{} src addr:{} protocol:{}'.format(
            dest_mac, src_mac, ether_proto))
        if ether_proto == 8:
            (version, header_length, ttl, ip_proto, src_ip, dest_ip,
             data) = ipv4_package(data)
            print(TAB_1 + 'IP package')
            print(TAB_2 + "version: {}, head length: {}, TTL={}".format(
                version, header_length, ttl))
            print(TAB_2 + "ip protocol:{}, source ip:{}, destination ip {}".
                  format(ip_proto, src_ip, dest_ip))

            if ip_proto == 1:
                (icmp_type, code, checksum, data) = icmp_package(data)
                print(TAB_2 + 'ICMP package')
                print(TAB_3 + "type: {}, code: {}, checksum: {}".format(
                    icmp_type, code, checksum))
                print(format_multi_line(DATA_TAB_3, data))

            elif ip_proto == 6:
                (src_port, dest_port, seq_num, ack_num, head_length, urg, ack,
                 psh, rst, syn, fin, data) = tcp_segement(data)
                print(TAB_2 + 'TCP segment')
                print(TAB_3 + 'source port: {}, destination port: {}'.format(
                    src_port, dest_port))
                print(TAB_3 + 'sequence number: {}, acknowledge number: {}'.
                      format(seq_num, ack_num))
                print(
                    TAB_3 + 'flags: URG:{} ACK:{} PSH:{} RST:{} SYN:{} FIN:{}'.
                    format(urg, ack, psh, rst, syn, fin))
                print(format_multi_line(DATA_TAB_3, data))

            elif ip_proto == 17:
                src_port, dest_port, length, checksum, data = udp_segement(
                    data)
                print(TAB_2 + 'UDP segment')
                print(TAB_3 + 'source port: {}, destination port: {}'.format(
                    src_port, dest_port))
                print(TAB_3 + 'udp length: {}, udp checksum: {}'.format(
                    length, checksum))
                print(format_multi_line(DATA_TAB_3, data))

            else:
                print(TAB_1 + 'DATA')
                print(format_multi_line(DATA_TAB_2, data))


def ether_frame(data):
    """unpackage the ether frame"""
    dest, src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac(dest), get_mac(src), socket.htons(proto), data[14:]


def get_mac(bytes_addr):
    """get formatted mac address (00:AA:BB:CC:DD:EE)"""
    mac_addr = map('{:02x}'.format, bytes_addr)
    return ':'.join(mac_addr).upper()


def ipv4_package(data):
    """unpackage ipv4 package"""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, source_ip, dest_ip = struct.unpack('!8x B B 2x 4s 4s',
                                                   data[:20])
    return version, header_length, ttl, proto, ipv4(source_ip), ipv4(
        dest_ip), data[header_length:]


def ipv4(bytes_addr):
    """formatted the ip address"""
    return '.'.join(map(str, bytes_addr))


def icmp_package(data):
    """unpackage icmp package"""
    icmp_type, code, checksum = struct.unpack("!B B H", data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segement(data):
    """unpackage tcp segement"""
    src_port, dest_port, seq_num, ack_num, header_reverse_flags = struct.unpack(
        "!H H I I H", data[:14])

    head_length = (header_reverse_flags >> 12) * 5
    flag_urg = (header_reverse_flags & 32) >> 5
    flag_ack = (header_reverse_flags & 16) >> 4
    flag_psh = (header_reverse_flags & 8) >> 4
    flag_rst = (header_reverse_flags & 4) >> 4
    flag_syn = (header_reverse_flags & 2) >> 4
    flag_fin = (header_reverse_flags & 1)

    return (src_port, dest_port, seq_num, ack_num, head_length, flag_urg,
            flag_ack, flag_psh, flag_rst, flag_syn, flag_fin,
            data[:head_length])


def udp_segement(data):
    """unpackage udp segement"""
    src_port, dest_port, length, checksum = struct.unpack("!H H H H", data[:8])
    return src_port, dest_port, length, checksum, data[8:]


def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    main()
