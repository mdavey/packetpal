import zlib
import struct


class PacpalMessage:

    @staticmethod
    def encode(callsign: bytes, data: bytes):
        if len(callsign) >= 10:
            raise Exception('Callsign must be 10 or less bytes')
        magic = b'PACPAL'
        version = b'\x01'
        callsign_padded = callsign + (b"\x00" * (10-len(callsign)))
        crc32 = struct.pack('I', zlib.crc32(data) & 0xffffffff)
        # 0x00 is for port 0 (for some reason...)
        return b'\x00' + magic + version + callsign_padded + b'\x00' + crc32 + data

    @staticmethod
    def decode(data: bytes):
        if data[0:6] != b'PACPAL':
            raise Exception('Magic Header missing')
        if data[6] == b'\x01':
            raise Exception('Wrong version found')
        callsign = data[7:17]
        reserved = data[17]
        sent_crc32 = struct.unpack('I', data[18:22])[0]
        data = data[22:]
        calculated_crc32 = zlib.crc32(data) & 0xffffffff
        if sent_crc32 != calculated_crc32:
            raise Exception('Bit error crc32 does not match')
        return data
