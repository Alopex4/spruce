#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.general import getIpv4, getMacAddr
from capturePkt.networkProtocol import NetworkProtocol


class DHCP(NetworkProtocol):
    DHCPFields = (
        'Opcode', 'Hardward Type', 'Hardware address length', 'Hop Count',
        'Transaction ID', 'Number of Seconds', 'Flags', 'Client IP Address',
        'Your IP Address', 'Server IP Address', 'Gateway IP Address',
        'Client hardware address', 'Server host name', 'Boot filename',
        'Magic Code', 'Options')
    opcodeDict = {1: '1 (Boot Request)', 2: '2 (Boot Reply)'}
    hardwardDict = {1: 'Ethernet',
                    2: 'Experimental Etherne',
                    3: 'Amateur Radio AX.25.',
                    4: 'Proteon ProNET Token Rin',
                    5: 'Chao',
                    6: 'IEEE 802',
                    7: 'ARCN',
                    8: 'Hyperchannel',
                    9: 'Lanstar',
                    10: 'Autonet Short Addres',
                    11: 'LocalTal',
                    12: 'LocalNet (IBM PCNet or SYTEK LocalNE)',
                    13: 'Ultra link',
                    14: 'SMDS',
                    15: 'Frame Relay',
                    16: 'ATM, Asynchronous Transmission Mode',
                    17: 'HDLC',
                    18: 'Fibre Channel',
                    19: 'ATM, Asynchronous Transmission Mode',
                    20: 'Serial Line',
                    21: 'ATM, Asynchronous Transmission Mode',
                    22: 'MIL-STD-188-220',
                    23: 'Metricom',
                    24: 'IEEE 1394.1995',
                    25: 'MAPOS',
                    26: 'Twinaxial',
                    27: 'EUI-64',
                    28: 'HIPARP',
                    29: 'IP and ARP over ISO 7816-3',
                    30: 'ARPSec',
                    31: 'IPsec tunnel',
                    32: 'Infiniband',
                    33: 'CAI, TIA-102 Project 25 Common Air Interface',
                    34: 'Wiegand Interfac',
                    35: 'Pure IP'}

    DHCPMsgTypeDict = {1: 'DHCPDISCOVER',
                       2: 'DHCPOFFER',
                       3: 'DHCPREQUEST',
                       4: 'DHCPDECLINE',
                       5: 'DHCPACK',
                       6: 'DHCPNAK',
                       7: 'DHCPRELEASE',
                       8: 'DHCPINFORM',
                       9: 'DHCPFORCERENEW',
                       10: 'DHCPLEASEQUERY',
                       11: 'DHCPLEASEUNASSIGNED',
                       12: 'DHCPLEASEUNKNOWN',
                       13: 'DHCPLEASEACTIVE',
                       14: 'DHCPBULKLEASEQUERY',
                       15: 'DHCPLEASEQUERYDONE',
                       16: 'DHCPACTIVELEASEQUERY',
                       17: 'DHCPLEASEQUERYSTATUS',
                       18: 'DHCPTLS',
                       }

    optionDict = {0: 'Pad',
                  1: 'Subnet Mask',
                  2: 'Time Offset',
                  3: 'Router',
                  4: 'Time Server',
                  5: 'Name Server',
                  6: 'Domain Server',
                  7: 'Log Server',
                  8: 'Quotes Server',
                  9: 'LPR Server',
                  10: 'Impress Server',
                  11: 'RLP Server',
                  12: 'Hostname',
                  13: 'Boot File Size',
                  14: 'Merit Dump File',
                  15: 'Domain Name',
                  16: 'Swap Server',
                  17: 'Root Path',
                  18: 'Extension File',
                  19: 'Forward On/Off',
                  20: 'SrcRte On/Off',
                  21: 'Policy Filter',
                  22: 'Max DG Assembly',
                  23: 'Default IP TTL',
                  24: 'MTU Timeout',
                  25: 'MTU Plateau',
                  26: 'MTU Interface',
                  27: 'MTU Subnet',
                  28: 'Broadcast Address',
                  29: 'Mask Discovery',
                  30: 'Mask Supplier',
                  31: 'Router Discovery',
                  32: 'Router Request',
                  33: 'Static Route',
                  34: 'Trailers',
                  35: 'ARP Timeout',
                  36: 'Ethernet',
                  37: 'Default TCP TTL',
                  38: 'Keepalive Time',
                  39: 'Keepalive Data',
                  40: 'NIS Domain',
                  41: 'NIS Servers',
                  42: 'NTP Servers',
                  43: 'Vendor Specific',
                  44: 'NETBIOS Name Srv',
                  45: 'NETBIOS Dist Srv',
                  46: 'NETBIOS Node Type',
                  47: 'NETBIOS Scope',
                  48: 'X Window Font',
                  49: 'X Window Manager',
                  50: 'Address Request',
                  51: 'Address Time',
                  52: 'Overload',
                  53: 'DHCP Msg Type',
                  54: 'DHCP Server Id',
                  55: 'Parameter List',
                  56: 'DHCP Message',
                  57: 'DHCP Max Msg Size',
                  58: 'Renewal Time',
                  59: 'Rebinding Time',
                  60: 'Class Id',
                  61: 'Client Id',
                  62: 'NetWare/IP Domain',
                  63: 'NetWare/IP Option',
                  64: 'NIS-Domain-Name',
                  65: 'NIS-Server-Addr',
                  66: 'Server-Name',
                  67: 'Bootfile-Name',
                  68: 'Home-Agent-Addrs',
                  69: 'SMTP-Server',
                  70: 'POP3-Server',
                  71: 'NNTP-Server',
                  72: 'WWW-Server',
                  73: 'Finger-Server',
                  74: 'IRC-Server',
                  75: 'StreetTalk-Server',
                  76: 'STDA-Server',
                  77: 'User-Class',
                  78: 'Directory Agent',
                  79: 'Service Scope',
                  80: 'Rapid Commit',
                  81: 'Client FQDN',
                  82: 'Relay Agent Information',
                  83: 'iSNS',
                  84: 'REMOVED/Unassigned',
                  85: 'NDS Servers',
                  86: 'NDS Tree Name',
                  87: 'NDS Context',
                  88: 'BCMCS Controller Domain Name list',
                  89: 'BCMCS Controller IPv4 address option',
                  90: 'Authentication',
                  91: 'client-last-transaction-time option',
                  92: 'associated-ip option',
                  93: 'Client System',
                  94: 'Client NDI',
                  95: 'LDAP',
                  96: 'REMOVED/Unassigned',
                  97: 'UUID/GUID',
                  98: 'User-Auth',
                  99: 'GEOCONF_CIVIC',
                  100: 'PCode',
                  101: 'TCode',
                  108: 'REMOVED/Unassigned',
                  109: 'OPTION_DHCP4O6_S46_SADDR',
                  110: 'REMOVED/Unassigned',
                  111: 'Unassigned',
                  112: 'Netinfo Address',
                  113: 'Netinfo Tag',
                  114: 'URL',
                  115: 'REMOVED/Unassigned',
                  116: 'Auto-Config',
                  117: 'Name Service Search',
                  118: 'Subnet Selection Option',
                  119: 'Domain Search',
                  120: 'SIP Servers DHCP Option',
                  121: 'Classless Static Route Option',
                  122: 'CCC',
                  123: 'GeoConf Option',
                  124: 'V-I Vendor Class',
                  125: 'V-I Vendor-Specific Information',
                  126: 'Removed/Unassigned',
                  127: 'Removed/Unassigned',
                  128: 'PXE - undefined (vendor specific)',
                  128: 'Etherboot signature. 6 bytes: E4:45:74:68:00:00',
                  128: 'DOCSIS "full security" server IP address',
                  128: 'TFTP Server IP address (for IP Phone software load)',
                  129: 'PXE - undefined (vendor specific)',
                  129: 'Kernel options. Variable length string',
                  129: 'Call Server IP address',
                  130: 'PXE - undefined (vendor specific)',
                  130: 'Ethernet interface. Variable length string.',
                  130: 'Discrimination string (to identify vendor)',
                  131: 'PXE - undefined (vendor specific)',
                  131: 'Remote statistics server IP address',
                  132: 'PXE - undefined (vendor specific)',
                  132: 'IEEE 802.1Q VLAN ID',
                  133: 'PXE - undefined (vendor specific)',
                  133: 'IEEE 802.1D/p Layer 2 Priority',
                  134: 'PXE - undefined (vendor specific)',
                  134: 'Diffserv Code Point (DSCP) for VoIP signalling and media streams',
                  135: 'PXE - undefined (vendor specific)',
                  135: 'HTTP Proxy for phone-specific applications',
                  136: 'OPTION_PANA_AGENT',
                  137: 'OPTION_V4_LOST',
                  138: 'OPTION_CAPWAP_AC_V4',
                  139: 'OPTION-IPv4_Address-MoS',
                  140: 'OPTION-IPv4_FQDN-MoS',
                  141: 'SIP UA Configuration Service Domains',
                  142: 'OPTION-IPv4_Address-ANDSF',
                  143: 'OPTION_V4_SZTP_REDIRECT',
                  144: 'GeoLoc',
                  145: 'FORCERENEW_NONCE_CAPABLE',
                  146: 'RDNSS Selection',
                  150: 'TFTP server address',
                  150: 'Etherboot',
                  150: 'GRUB configuration path name',
                  151: 'status-code',
                  152: 'base-time',
                  153: 'start-time-of-state',
                  154: 'query-start-time',
                  155: 'query-end-time',
                  156: 'dhcp-state',
                  157: 'data-source',
                  158: 'OPTION_V4_PCP_SERVER',
                  159: 'OPTION_V4_PORTPARAMS',
                  160: 'DHCP Captive-Portal',
                  161: 'OPTION_MUD_URL_V4',
                  175: 'Etherboot (Tentatively Assigned - 2005-06-23)',
                  176: 'IP Telephone (Tentatively Assigned - 2005-06-23)',
                  177: 'Etherboot (Tentatively Assigned - 2005-06-23)',
                  177: 'PacketCable and CableHome (replaced by 122)',
                  208: 'PXELINUX Magic',
                  209: 'Configuration File',
                  210: 'Path Prefix',
                  211: 'Reboot Time',
                  212: 'OPTION_6RD',
                  213: 'OPTION_V4_ACCESS_DOMAIN',
                  220: 'Subnet Allocation Option',
                  221: 'Virtual Subnet Selection (VSS) Option',
                  255: 'End',
                  }

    def __init__(self, packet):
        dhcp = unpack('!B B B B I H H 4s 4s 4s 4s 6s 10x 64s 128s I',
                      packet[:240])
        self.opcode = DHCP.opcodeDict.get(dhcp[0], 'Unknown')
        self.hwtype = DHCP.hardwardDict.get(dhcp[1], 'Unknown')
        self.hwlen = '{} bytes'.format(dhcp[2])
        self.hops = dhcp[3]
        self.transID = '0x{:08x}'.format(dhcp[4])
        self.numberOfSec = dhcp[5]
        self.flags = 'Broadcast' if dhcp[6] >> 15 == 1 else 'Unicast'
        self.cliIP = getIpv4(dhcp[7])
        self.yourIP = getIpv4(dhcp[8])
        self.sererIP = getIpv4(dhcp[9])
        self.gwIP = getIpv4(dhcp[10])
        self.clihw = getMacAddr(dhcp[11])
        self.hostName = dhcp[12].decode('utf-8', 'ignore')
        self.bootFile = dhcp[13].decode('utf-8', 'ignore')
        self.magicCookie = '0x{:04x}'.format(dhcp[14])
        self.option = '-------'
        self.extendField = tuple()
        self.extendParse = tuple()
        self.optionParse(packet[240:])

    def optionParse(self, pkt):
        opValue = pkt[0]
        while opValue != 255:
            if opValue == 53:
                opParse = DHCP.DHCPMsgTypeDict.get(pkt[2], 'Unknown')
            else:
                opParse = DHCP.optionDict.get(opValue, 'Unknown')
            opLen = pkt[1]
            self.extendField = self.extendField + (
                '    Option Name', '    Option Length')
            self.extendParse = self.extendParse + (opParse, opLen)
            pkt = pkt[opLen + 2:]
            opValue = pkt[0]

    def getFields(self):
        fields = DHCP.DHCPFields + self.extendField
        return fields

    def getParses(self):
        parses = (self.opcode, self.hwtype, self.hwlen, self.hops,
                  self.transID, self.numberOfSec, self.flags, self.cliIP,
                  self.yourIP, self.sererIP, self.gwIP, self.clihw,
                  self.hostName, self.bootFile, self.magicCookie,
                  self.option) + self.extendParse
        return parses
