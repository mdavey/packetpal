import socket
import sys
import threading
import struct
import time
import zlib


class SimpleTcpClient:
    """
    Stolen from mboukhlouf/tinytcp

    I think this is too simple.  I actually need to parse headers and manually group frames raw data into AGWPE
    frames...  I'm not looking forward to that, it seems really complicated (how do I tell the difference between an
    incomplete header, and corrupted data?  How long do I wait for the rest of the data?).

    Aha, steal this too:
    https://github.com/HenkVanAsselt/pyagw/blob/master/src/agwpe.py#L156


    multiple event handlers for incoming data by:
    def i_got_data(bytes):
        print(repr(bytes))

    client = SimpleTcpClient()
    client.on_data.append(i_got_data)
    client.connect()
    client.start_read_loop()

    client.send(b"Raw Packet")
    """

    def __init__(self):
        self._socket = None
        self._thread = None

        self.on_data = []
        self.on_shutdown = []

    @staticmethod
    def _trigger_event(what, *args):
        for f in what:
            f(*args)

    def _wait_for_data(self):
        while True:
            try:
                buffer = self._socket.recv(1024*8)
            except OSError:
                self._trigger_event(self.on_shutdown, 'OSError')
                break
            if len(buffer) == 0:
                self._trigger_event(self.on_shutdown, 'NoData')
                break

            self._trigger_event(self.on_data, buffer)

    def connect(self, host: str, port: int):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((host, port))

    def start_read_loop(self):
        self._thread = threading.Thread(target=self._wait_for_data)
        self._thread.start()

    def stop(self):
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()

    def send(self, msg: bytes):
        self._socket.sendall(msg)


class AgwpePacket:
    """
    This is the standard header for AGWPE packets
    Sending and receiving is the same format

    Safe to ignore reserved parts

    Everything should be bytes

    Fill in a new Packet and call encode() to get raw packet to send

    Pass a raw packet to AgwpePacket.decode() to get a AgwpePacket object
    """
    def __init__(self):
        self.port = b"\x00"
        self.reserved1 = b"\x00"
        self.reserved2 = b"\x00"
        self.reserved3 = b"\x00"
        self.kind = b"R"
        self.reserved4 = b"\x00"
        self.pid = b"\x00"
        self.reserved5 = b"\x00"
        self.call_from = b"\x00" * 10
        self.call_to = b"\x00" * 10
        self.data_len = 0
        self.user = b"\x00" * 4
        self.data = b""

    def __str__(self):
        return "\n".join([
            'port ' + repr(self.port),
            'kind ' + repr(self.kind),
            'call_from ' + repr(self.call_from),
            'call_to ' + repr(self.call_to),
            'user' + repr(self.user),
            'data_len ' + repr(self.data_len),
            'data' + repr(self.data),
            'data ' + ' '.join([hex(ch) for ch in self.data]),
        ])

    def set_kind(self, kind: str):
        if len(kind) != 1:
            raise NameError("Kind must be a single ascii character")
        self.kind = kind.encode('ASCII')

    def set_call_from(self, who: str):
        if len(who) > 9:
            raise NameError("String must be <9 characters")
        self.call_from = who.encode('ASCII')
        self.call_from += b"\x00" * (10-len(self.call_from))

    def set_call_to(self, who: str):
        if len(who) > 9:
            raise NameError("String must be <9 characters")
        self.call_to = who.encode('ASCII')
        self.call_to += b"\x00" * (10-len(self.call_to))

    def set_data(self, data: bytes):
        # Good practice says 255.  But, I'm looking for practical results...
        # if len(data) > 255:
        #     raise NameError("String must be <255 characters")
        self.data = data
        self.data_len = len(data)

    def encode(self) -> bytes:
        return self.port + \
               self.reserved1 + \
               self.reserved2 + \
               self.reserved3 + \
               self.kind + \
               self.reserved4 + \
               self.pid + \
               self.reserved5 + \
               self.call_from + \
               self.call_to + \
               struct.pack("i", self.data_len) + \
               self.user + \
               self.data

    @staticmethod
    def decode(raw: bytes):
        """
        Um, what happens when it cannot decode?
        """
        data_len = len(raw) - 36
        parts = struct.unpack("BBBBcBBB10s10sI4s" + str(data_len)+"s", raw)

        p = AgwpePacket()
        p.port = parts[0]
        p.reserved1 = parts[1]
        p.reserved2 = parts[2]
        p.reserved3 = parts[3]
        p.kind = parts[4]
        p.reserved4 = parts[5]
        p.pid = parts[6]
        p.reserved5 = parts[7]
        p.call_from = parts[8]
        p.call_to = parts[9]
        p.data_len = parts[10]
        p.user = parts[11]
        p.data = parts[12]

        return p


# Just to make sure all AgwpeClients call the events one-by-one
AgwpeClientMutex = threading.Lock()


class AgwpeClient:
    def __init__(self):
        self.tcp_client = SimpleTcpClient()

        self.on_version_info = []
        self.on_unknown_packet = []
        self.on_raw_packet = []
        self.on_outstanding_frames = []

    def connect(self, host: str, port: int):
        self.tcp_client.on_data.append(self._handle_data)
        self.tcp_client.connect(host, port)
        self.tcp_client.start_read_loop()

    def disconnect(self):
        self.tcp_client.stop()

    @staticmethod
    def _trigger_event(what, *args):
        for f in what:
            f(*args)

    def _handle_data(self, data: bytes):
        try:
            AgwpeClientMutex.acquire()
            packet = AgwpePacket.decode(data)

            if packet.kind == b'R':  # version response
                (major, minor) = struct.unpack('HxxHxx', packet.data)  # this is wrong, or at least weird? 2005 127 ?
                self._trigger_event(self.on_version_info, major, minor)
            elif packet.kind == b'K':
                self._trigger_event(self.on_raw_packet, packet.data[1:])  # first byte is port number (so ignore)
            elif packet.kind == b'y':
                self._trigger_event(self.on_outstanding_frames, struct.unpack('I', packet.data)[0])
            else:
                print(packet)
                self._trigger_event(self.on_unknown_packet, packet)

        except Exception as e:
            print("Unable to decode packet")
            print(e)
        finally:
            AgwpeClientMutex.release()
            pass

    def request_version_info(self):
        packet = AgwpePacket()
        packet.set_kind('R')
        self.tcp_client.send(packet.encode())

    def request_port_info(self):
        packet = AgwpePacket()
        packet.set_kind('G')
        self.tcp_client.send(packet.encode())

    def request_port_capabilities(self):
        packet = AgwpePacket()
        packet.set_kind('g')
        self.tcp_client.send(packet.encode())

    def request_outstanding_frames(self):
        packet = AgwpePacket()
        packet.set_kind('y')
        self.tcp_client.send(packet.encode())

    def register_callsign(self, callsign):
        packet = AgwpePacket()
        packet.set_kind('X')
        packet.set_call_from(callsign)
        self.tcp_client.send(packet.encode())

    def enable_monitoring(self):
        packet = AgwpePacket()
        packet.set_kind('m')
        self.tcp_client.send(packet.encode())

    def enable_raw_monitoring(self):
        packet = AgwpePacket()
        packet.set_kind('k')
        self.tcp_client.send(packet.encode())

    def send_unproto(self, call_from, call_to, data: bytes):
        packet = AgwpePacket()
        packet.set_kind('M')
        packet.set_call_from(call_from)
        packet.set_call_to(call_to)
        packet.set_data(data)
        self.tcp_client.send(packet.encode())

    def send_raw_packet(self, data: bytes):
        packet = AgwpePacket()
        packet.set_kind('K')
        packet.set_data(data)
        self.tcp_client.send(packet.encode())


def encode_pacpal_message(callsign: bytes, data: bytes):
    if len(callsign) >= 10:
        raise Exception('Callsign must be 10 or less bytes')
    magic = b'PACPAL'
    version = b'\x01'
    callsign_padded = callsign + (b"\x00" * (10-len(callsign)))
    length = struct.pack('B', len(data))
    crc32 = struct.pack('I', zlib.crc32(data) & 0xffffffff)
    return b'\x00' + magic + version + callsign_padded + length + crc32 + data  # 0x00 is for port 0 (for some reason...)


def decode_pacpal_message(data: bytes):
    if data[0:6] != b'PACPAL':
        raise Exception('Magic Header missing')
    if data[6] == b'\x01':
        raise Exception('Wrong version found')
    callsign = data[7:17]
    length = data[17]
    sent_crc32 = struct.unpack('I', data[18:22])[0]
    data = data[22:]
    calculated_crc32 = zlib.crc32(data) & 0xffffffff
    if sent_crc32 != calculated_crc32:
        raise Exception('Bit error crc32 does not match')
    return data


def transfer_data(host: str, port: int, callsign: bytes, data: bytes):
    chuck_size = 256-22
    buffer_size = 4

    agwpe = AgwpeClient()
    agwpe.connect(host, port)

    outstanding_frames = 0

    def update_outstanding_frames(new: int):
        nonlocal outstanding_frames
        outstanding_frames = new

    agwpe.on_outstanding_frames.append(update_outstanding_frames)

    for offset in range(0, len(data), chuck_size):
        print('offset', offset, 'len', len(data))
        if len(data) > offset+chuck_size:
            d = data[offset:offset+chuck_size]
        else:
            d = data[offset:]

        print(d.hex(' ', 1))

        while outstanding_frames > buffer_size:
            print('Waiting for buffer to empty, current outstanding frames:', outstanding_frames)
            agwpe.request_outstanding_frames()
            time.sleep(0.1)

        agwpe.send_raw_packet(encode_pacpal_message(callsign, d))
        agwpe.request_outstanding_frames()
        time.sleep(0.1)

    agwpe.disconnect()


def handle_version(major, minor):
    print("Version", major, minor)


def handle_raw_packet(data: bytes):
    try:
        # Try and decode to see if it's a pacpal message
        msg = decode_pacpal_message(data)
        print('Received data', msg.hex(' ', 1))
    except Exception as e:
        print('Got raw packet, but failed to decode', e)


def handle_outstanding_frames(outstanding_frames: int):
    print('Outstanding frames:', outstanding_frames)


if __name__ == '__main__':
    recv_client = AgwpeClient()

    try:
        recv_client.connect('localhost', 8000)
        recv_client.enable_raw_monitoring()
        recv_client.on_raw_packet.append(handle_raw_packet)

        data = b'\x00\x01\x02\x03\x04\x05\x06\x07'
        transfer_data('localhost', 9000, b'VK3ARD', data * 1024)

        time.sleep(2)
    finally:
        recv_client.disconnect()


# if __name__ == '__main__':
#
#     client1 = AgwpeClient()
#     client2 = AgwpeClient()
#
#     try:
#         # SoundModem_HS 1
#         client1.connect('localhost', 8000)
#
#         client1.enable_raw_monitoring()
#         client1.on_raw_packet.append(handle_raw_packet)
#
#         # SoundModem_HS 2
#         client2.connect('localhost', 9000)
#         client2.on_outstanding_frames.append(handle_outstanding_frames)
#         client2.request_port_info()
#         client2.request_port_capabilities()
#         # client2.enable_monitoring()
#
#         time.sleep(0.5)
#
#         messages_to_send = [
#             b'\x01\x02\x03\x04\x05\x06\x07',
#             b'\x08\x09\x0A\x0B\x0C\x0D\x0E',
#             b'\x0F\x10\x11\x12\x13\x14\x15'
#         ]
#
#         for x in range(1, 8):
#             for msg in messages_to_send:
#                 print('Client 2 sending:', msg.hex(' ', 1))
#                 client2.send_raw_packet(encode_pacpal_message(b'VK3ARD', msg * 8))
#
#         for x in range(1, 32):
#             # This just always returns '0'
#             # Was this all a giant waste of time?
#             # I need to know how much data is waiting to be sent.
#             # QTSoundModem just ignores it completely
#             #
#             # I don't know what I can do except for listening to the audio device itself to tell when data has been
#             # transmitted... Which is insane, and still doesn't get what I want.
#             #
#             # How the hell does everyone else manage flow control?
#             #
#             # Does everyone just ignore it?
#             #
#             # Answer:
#             # Direwolf support the 'y' frame but only for *real* AX.25 packets
#             # I've built my own version of 1.7.0 with a single change:
#             # tq.c:987 [-]      if (ax25_get_num_addr(pp) >= AX25_MIN_ADDRS) {
#             # tq.c:987 [+]      if (TRUE || ax25_get_num_addr(pp) >= AX25_MIN_ADDRS) {
#             #
#             # Probably not a good idea, but it looks like it works, and I can now do flow control for raw frames
#             client2.request_outstanding_frames()
#             time.sleep(0.5)
#
#     finally:
#         client1.disconnect()
#         client2.disconnect()
#
