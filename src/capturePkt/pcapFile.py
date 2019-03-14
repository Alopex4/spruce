import struct


class PcapFile:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(
            struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535,
                        link_type))

    def write(self, data, tsSec, tsUsec):
        # ts_sec, ts_usec = (int(ts.ljust(6, '0')) if len(ts) < 6 else int(ts)
        #                    for ts in str(round(time.time(), 6)).split('.'))
        length = len(data)
        self.pcap_file.write(
            struct.pack('@ I I I I', tsSec, tsUsec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()
