#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from re import findall
from string import printable
from struct import unpack

from capturePkt.networkProtocol import NetworkProtocol


class Telnet(NetworkProtocol):
    IAC = 0xff
    codeDict = {236: 'EOF',
                237: 'SUSP',
                238: 'ABORT',
                239: 'EOR',
                240: 'SE',
                241: 'NOP',
                242: 'DM',
                243: 'BRK',
                244: 'IP',
                245: 'AO',
                246: 'AYT',
                247: 'EC',
                248: 'EL',
                249: 'GA',
                250: 'SB',
                251: 'WILL',
                252: 'WONT',
                253: 'DO',
                254: 'DONT',
                255: 'IAC',
                }
    # https://www.iana.org/assignments/telnet-options/telnet-options.xhtml
    optionDict = {0: 'Binary Transmission',
                  1: 'Echo',
                  2: 'Reconnection',
                  3: 'Suppress Go Ahead',
                  4: 'Approx Message Size Negotiation',
                  5: 'Status',
                  6: 'Timing Mark',
                  7: 'Remote Controlled Trans and Echo',
                  8: 'Output Line Width',
                  9: 'Output Page Size',
                  10: 'Output Carriage-Return Disposition',
                  11: 'Output Horizontal Tab Stops',
                  12: 'Output Horizontal Tab Disposition',
                  13: 'Output Formfeed Disposition',
                  14: 'Output Vertical Tabstops',
                  15: 'Output Vertical Tab Disposition',
                  16: 'Output Linefeed Disposition',
                  17: 'Extended ASCII',
                  18: 'Logout',
                  19: 'Byte Macro',
                  20: 'Data Entry Terminal',
                  21: 'SUPDUP',
                  22: 'SUPDUP Output',
                  23: 'Send Location',
                  24: 'Terminal Type',
                  25: 'End of Record',
                  26: 'TACACS User Identification',
                  27: 'Output Marking',
                  28: 'Terminal Location Number',
                  29: 'Telnet 3270 Regime',
                  30: 'X.3 PAD',
                  31: 'Negotiate About Window Size',
                  32: 'Terminal Speed',
                  33: 'Remote Flow Control',
                  34: 'Linemode',
                  35: 'X Display Location',
                  36: 'Environment Option',
                  37: 'Authentication Option',
                  38: 'Encryption Option',
                  39: 'New Environment Option',
                  40: 'TN3270E',
                  41: 'XAUTH',
                  42: 'CHARSET',
                  43: 'Telnet Remote Serial Port (RSP)',
                  44: 'Com Port Control Option',
                  45: 'Telnet Suppress Local Echo',
                  46: 'Telnet Start TLS',
                  47: 'KERMIT',
                  48: 'SEND-URL',
                  49: 'FORWARD_X',
                  138: 'TELOPT PRAGMA LOGON',
                  139: 'TELOPT SSPI LOGON',
                  140: 'TELOPT PRAGMA HEARTBEAT',
                  255: 'Extended-Options-List',
                  }

    def __init__(self, packet):
        self.extendField = tuple()
        self.extendParse = tuple()

        while packet:
            if packet[0] == self.IAC:
                telnet = unpack('!B B', packet[1:3])
                self.code = Telnet.codeDict.get(telnet[0], 'Unknown')
                self.option = Telnet.optionDict.get(telnet[1], 'Unknown')
                commandStr = '{} {}'.format(self.code, self.option)
                self.extendField = self.extendField + ('Telnet Command',)
                self.extendParse = self.extendParse + (commandStr,)
                packet = packet[3:]
                continue
            else:
                data = packet.decode('utf-8', 'ignore')
                data = list(filter(lambda x: x in printable, data))
                data = ''.join(data)
                if len(data) > 80:
                    data = '\n'.join(findall(r'.{80}', data))
                else:
                    data = data.replace('\r\n', '')
                self.extendField = self.extendField + ('Data',)
                self.extendParse = self.extendParse + (data,)
                break

    def getFields(self):
        return self.extendField

    def getParses(self):
        return self.extendParse
