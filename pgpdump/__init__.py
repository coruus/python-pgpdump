from base64 import b64decode

from .packet import construct_packet

BINARY_TAG_FLAG = 0x80

class BinaryData(object):
    '''The base object used for extracting PGP data packets. This expects fully
    binary data as input; such as that read from a .sig or .gpg file.'''
    def __init__(self, data):
        if not data:
            raise Exception("no data to parse")
        if len(data) <= 1:
            raise Exception("data too short")

        # convert any bytes/str instance to a list of ints
        if isinstance(data, bytes):
            data = [ord(c) for c in data]

        # 7th bit of the first byte must be a 1
        if not bool(data[0] & BINARY_TAG_FLAG):
            raise Exception("incorrect binary data")
        self.data = data
        self.length = len(data)

    def packets(self):
        '''A generator function returning PGP data packets.'''
        offset = 0
        while offset < len(self.data):
            total_length, packet = construct_packet(self.data[offset:])
            offset += total_length
            yield packet

    def __repr__(self):
        return "<%s: length %d>" % (
                self.__class__.__name__, self.length)

class AsciiData(BinaryData):
    '''A wrapper class that supports ASCII-armored input. It searches for the
    first PGP magic header and extracts the data contained within.'''
    def __init__(self, data):
        self.original_data = data
        data = self.strip_magic(data)
        data, known_crc = self.split_data_crc(data)
        data = [ord(c) for c in b64decode(data)]
        if known_crc:
            # verify it if we could find it
            actual_crc = self.crc24(data)
            if known_crc != actual_crc:
                raise Exception("CRC failure: known 0x%x, actual 0x%x" % (
                    known_crc, actual_crc))
        super(AsciiData, self).__init__(data)

    @staticmethod
    def strip_magic(data):
        '''Strip away the '-----BEGIN PGP SIGNATURE-----' and related cruft so
        we can safely base64 decode the remainder.'''
        magic = '-----BEGIN PGP '
        #ignore = '-----BEGIN PGP SIGNED '

        # find our magic string
        idx = data.find(magic)
        if idx >= 0:
            # find the start of the actual data. it always immediately follows
            # a blank line, meaning headers are done.
            nl_idx = data.find('\n\n', idx)
            if nl_idx < 0:
                nl_idx = data.find('\r\n\r\n', idx)
            if nl_idx < 0:
                raise Exception("found magic, could not find start of data")
            # now find the end of the data.
            end_idx = data.find('-----', nl_idx)
            if end_idx:
                data = data[nl_idx:end_idx]
            else:
                data = data[nl_idx:]
        return data

    @staticmethod
    def split_data_crc(data):
        '''The Radix-64 format appends any CRC checksum to the end of the data
        block, in the form '=alph', where there are always 4 ASCII characters
        correspnding to 3 digits (24 bits). Look for this special case.'''
        # don't let newlines trip us up
        data = data.strip()
        if data[-5] == '=':
            # CRC is returned without the = and converted to a decimal
            crc = b64decode(data[-4:])
            crc = (ord(crc[0]) << 16) + (ord(crc[1]) << 8) + ord(crc[2])
            return (data[:-5], crc)
        return (data, None)

    @staticmethod
    def crc24(data):
        '''Implementation of the OpenPGP CRC-24 algorithm.'''
        # CRC-24-Radix-64
        # x24 + x23 + x18 + x17 + x14 + x11 + x10 + x7 + x6
        #   + x5 + x4 + x3 + x + 1 (OpenPGP)
        # 0x864CFB / 0xDF3261 / 0xC3267D
        crc = 0x00b704ce
        for byte in data:
            crc ^= (byte << 16)
            # optimization: don't have to call range(8) here
            for _ in (0, 1, 2, 3, 4, 5, 6, 7):
                crc <<= 1
                if crc & 0x01000000:
                    crc ^= 0x00864cfb
            crc &= 0x00ffffff
        return crc
