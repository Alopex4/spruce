#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class ICMPv6(NetworkProtocol):
    ICMPv6Fields = ('Type', 'Code', 'Checksum', 'Message Type')
    # https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml
    TypeCodeDict = {0: 'Reserved',
                    1: {0: 'No route to destination',
                        1: 'Communication with destination administratively prohibited',
                        2: 'Beyond scope of source address',
                        3: 'Address unreachable',
                        4: 'Port unreachable',
                        5: 'Source address failed ingress/egress policy',
                        6: 'Reject route to destination',
                        7: 'Error in Source Routing Header',
                        },
                    2: {0: 'Packet Too Big'},
                    3: {0: 'Hop limit exceeded in transit',
                        1: 'Fragment reassembly time exceeded', },
                    4: {0: 'Erroneous header field encountered',
                        1: 'Unrecognized Next Header type encountered',
                        2: 'Unrecognized IPv6 option encountered',
                        },
                    128: {0: 'Echo Request'},
                    129: {0: 'Echo Reply'},
                    130: {0: 'Multicast Listener Query'},
                    131: {0: 'Multicast Listener Report'},
                    132: {0: 'Multicast Listener Done'},
                    133: {0: 'Router Solicitation'},
                    134: {0: 'Router Advertisement'},
                    135: {0: 'Neighbor Solicitation'},
                    136: {0: 'Neighbor Advertisement'},
                    137: {0: 'Redirect Message'},
                    138: {
                        0: 'Router Renumbering Command',
                        1: 'Router Renumbering Result',
                        255: 'Sequence Number Reset', },
                    139: {
                        0: 'The Data field contains an IPv6 address ',
                        1: 'The Data field contains a name ',
                        2: 'The Data field contains an IPv4 ', },
                    140: {
                        0: 'A successful reply. The Reply Data field may or may not be empty.',
                        1: 'The Responder refuses to supply the answer',
                        2: 'The Qtype of the Query is unknown to the Responder. ', },
                    141: {0: 'Inverse Neighbor Discovery Solicitation Message'},
                    142: {
                        0: 'Inverse Neighbor Discovery Advertisement Message'},
                    143: {0: 'Version 2 Multicast Listener Report'},
                    144: {0: 'Home Agent Address Discovery Request Message'},
                    145: {0: 'Home Agent Address Discovery Reply Message'},
                    146: {0: 'Mobile Prefix Solicitation'},
                    147: {0: 'Mobile Prefix Advertisement'},
                    148: {0: 'Certification Path Solicitation Message'},
                    149: {0: 'Certification Path Advertisement Message'},
                    150: {
                        0: 'ICMP messages utilized by experimental mobility protocols such as Seamoby'},
                    151: {0: 'Multicast Router Advertisement'},
                    152: {0: 'Multicast Router Solicitation'},
                    153: {0: 'Multicast Router Termination'},
                    154: {0: 'FMIPv6 Messages'},
                    155: {0: 'RPL Control Message'},
                    156: {0: 'ILNPv6 Locator Update Message'},
                    157: {0: 'Duplicate Address Request'},
                    158: {0: 'Duplicate Address Confirmation'},
                    159: {0: 'MPL Control Message'},
                    160: {0: 'Extended Echo Request'},
                    161: {0: 'Extended Echo Reply'},
                    }

    def __init__(self, packet):
        self.icmpv6 = unpack('!B B H', packet[:4])
        self.type = '0x{:04x} ({})'.format(self.icmpv6[0], self.icmpv6[0])
        self.code = '0x{:04x} ({})'.format(self.icmpv6[1], self.icmpv6[1])
        self.checksum = '0x{:04x} ({})'.format(self.icmpv6[2], self.icmpv6[2])
        try:
            self.messageType = ICMPv6.TypeCodeDict.get(self.icmpv6[0]).get(
                self.icmpv6[1])
        except AttributeError:
            self.messageType = 'Unknown'

    def getFields(self):
        return ICMPv6.ICMPv6Fields

    def getParses(self):
        parses = (self.type, self.code, self.checksum, self.messageType)
        return parses
