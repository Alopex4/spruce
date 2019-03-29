#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class Domain(NetworkProtocol):
    DomainFields = (
        'Identification', 'flags', '    Query or Response', '    Option Code',
        '    Authoritative Answer(AA)', '    Truncated(TC)',
        '     Recursion Desired(RD)', '    Recursion Available(RA)',
        '    (Zero)', '    Return Code', 'Number of Questions',
        'Number of Answer RRs', 'Number of Authority RRs',
        'Number of additional RRs', 'Questions')

    opCodeDict = {0: '0x0 Standard Query', 1: '0x1 Inverse Query',
                  2: '0x2 Server Status Request'}

    rcCodeDict = {0: '0x0 (No Error)', 2: '0x2 (Server Failure)',
                  3: '0x3 (Name Error)'}
    # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
    typeDict = {
        1: 'A a host address',
        2: 'NS an authoritative name server',
        3: 'MD a mail destination (OBSOLETE - use MX)',
        4: 'MF a mail forwarder (OBSOLETE - use MX)',
        5: 'CNAME the canonical name for an alias',
        6: 'SOA	marks the start of a zone of authority',
        7: 'MB a mailbox domain name (EXPERIMENTAL)',
        8: 'MG a mail group member (EXPERIMENTAL)',
        9: 'MR a mail rename domain name (EXPERIMENTAL)',
        10: 'NULL a null RR (EXPERIMENTAL)',
        11: 'WKS a well known service description',
        12: 'PTR a domain name pointer',
        13: 'HINFO host information',
        14: 'MINFO mailbox or mail list information',
        15: 'MX mail exchange',
        16: 'TXT text strings',
        17: 'RP for Responsible Person',
        18: 'AFSDB for AFS Data Base location',
        19: 'X25 for X.25 PSDN address',
        20: 'ISDN for ISDN address',
        21: 'RT for Route Through',
        22: 'NSAP for NSAP address, NSAP style A record',
        23: 'NSAP-PTR for domain name pointer, NSAP style',
        24: 'SIG for security signature',
        25: 'KEY for security key',
        26: 'PX	X.400 mail mapping information',
        27: 'GPOS Geographical Position',
        28: 'AAAA IP6 Address',
        29: 'LOC Location Information',
        30: 'NXT Next Domain (OBSOLETE)',
        31: 'EID Endpoint Identifier',
        32: 'NIMLOC	Nimrod Locator',
        33: 'SRV Server Selection',
        34: 'ATMA ATM Address',
        35: 'NAPTR Naming Authority Pointer',
        36: 'KX	Key Exchanger',
        37: 'CERT CERT',
        38: 'A6	A6 (OBSOLETE - use AAAA)',
        39: 'DNAME DNAME',
        40: 'SINK SINK',
        41: 'OPT OPT',
        42: 'APL APL',
        43: 'DS	Delegation Signer',
        44: 'SSHFP SSH Key Fingerprint',
        45: 'IPSECKEY IPSECKEY',
        46: 'RRSIG RRSIG',
        47: 'NSEC NSEC',
        48: 'DNSKEY	DNSKEY',
        49: 'DHCID DHCID',
        50: 'NSEC3 NSEC3',
        51: 'NSEC3PARAM	NSEC3PARAM',
        52: 'TLSA TLSA',
        53: 'SMIMEA	S/MIME cert association',
        54: 'Unassigned	',
        55: 'HIP Host Identity Protocol',
        56: 'NINFO NINFO',
        57: 'RKEY RKEY',
        58: 'TALINK	Trust Anchor LINK',
        59: 'CDS Child DS',
        60: 'CDNSKEY DNSKEY(s) the Child wants reflected in DS',
        61: 'OPENPGPKEY	OpenPGP Key',
        62: 'CSYNC Child-To-Parent Synchronization',
        63: 'ZONEMD	message digest for DNS zone',
        99: 'SPF',
        100: 'UINFO',
        101: 'UID',
        102: 'GID',
        103: 'UNSPEC',
        104: 'NID',
        105: 'L32',
        106: 'L64',
        107: 'LP',
        108: 'EUI48	an EUI-48 address',
        109: 'EUI64	an EUI-64 address',
        249: 'TKEY Transaction Key',
        250: 'TSIG Transaction Signature',
        251: 'IXFR incremental transfer',
        252: 'AXFR transfer of an entire zone',
        253: 'MAILB	mailbox-related RRs (MB, MG or MR)',
        254: 'MAILA	mail agent RRs (OBSOLETE - see MX)',
        256: 'URI URI',
        257: 'CAA Certification Authority Restriction',
        258: 'AVC Application Visibility and Control',
        259: 'DOA Digital Object Architecture',
        260: 'AMTRELAY Automatic Multicast Tunneling Relay',
    }

    def __init__(self, packet):
        self.packt = packet
        domain = unpack('!H H H H H H', self.packet[:12])
        self.identification = '0x{:04x}'.format(domain[0])
        self.flags = '0x{:04x}'.format(domain[1])
        self.qr = '1 (Response)' if domain[1] >> 15 == 1 else '0 (Query)'
        self.opCode = Domain.opCodeDict.get((domain[1] & 0x78) >> 11, 'Unknown')
        self.aa = '1' if domain[1] & 0x0400 else '0'
        self.tc = '1' if domain[1] & 0x0200 else '0'
        self.rd = '1' if domain[1] & 0x0100 else '0'
        self.ra = '1' if domain[1] & 0x0080 else '0'
        self.zero = '0x {:03x}'.format((domain[1] & 0x0070) >> 4)
        self.rcode = Domain.rcCodeDict.get(domain[1] & 0x000f, 'Unknown')
        self.numOfQues = domain[2]
        self.numOfAnsRRs = domain[3]
        self.numOfAuthRRs = domain[4]
        self.numofAdditRRs = domain[5]

        self.packet = self.packet[12:]
        self.question = self.questionParse(
            self.packet) if self.numOfQues else 'No Questions'

    def questionParse(self, pkt):
        queryList = []

        count = pkt[0]
        while count != 0:
            subQuery, *_ = unpack(self._getDomainName(count), pkt[1:count + 1])
            pkt = pkt[count + 1:]
            queryList.append(subQuery.decode('utf-8'))
            count = pkt[0]

        pkt = pkt[count + 1:]
        queryStr = '.'.join(queryList)
        typeClass = unpack('!H H', pkt[:4])
        type = Domain.typeDict.get(typeClass[0], 'Unknown')
        classx = 'IN' if typeClass[1] == 1 else 'Unknown'
        self.packet = pkt[4:]

        return queryStr + '\n' + type + '\n' + classx

    def _getDomainName(self, count):
        return '!{}s'.format(count)

    def getFields(self):
        return Domain.DomainFields

    def getParses(self):
        parses = (
            self.identification, self.flags, self.qr, self.opCode, self.aa,
            self.tc, self.rd, self.ra, self.zero, self.rcode,
            self.numOfQues, self.numOfAnsRRs, self.numOfAuthRRs,
            self.numofAdditRRs,
            self.question)
        return parses
