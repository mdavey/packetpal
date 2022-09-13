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
    crc32 = struct.pack('I', zlib.crc32(data) & 0xffffffff)
    # 0x00 is for port 0 (for some reason...)
    return b'\x00' + magic + version + callsign_padded + b'\x00' + crc32 + data


def decode_pacpal_message(data: bytes):
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


def transfer_data(host: str, port: int, callsign: bytes, data: bytes):
    # chuck_size = 256-22
    chuck_size = 512-22
    # chuck_size = 1024-22
    buffer_size = 4

    agwpe = AgwpeClient()
    agwpe.connect(host, port)

    outstanding_frames = 0

    def update_outstanding_frames(new: int):
        nonlocal outstanding_frames
        outstanding_frames = new

    agwpe.on_outstanding_frames.append(update_outstanding_frames)

    for offset in range(0, len(data), chuck_size):
        # print('offset', offset, 'len', len(data))
        if len(data) > offset+chuck_size:
            d = data[offset:offset+chuck_size]
        else:
            d = data[offset:]

        while outstanding_frames > buffer_size:
            # print('Waiting for buffer to empty, current outstanding frames:', outstanding_frames)
            agwpe.request_outstanding_frames()
            time.sleep(0.1)

        agwpe.send_raw_packet(encode_pacpal_message(callsign, d))
        agwpe.request_outstanding_frames()
        time.sleep(0.1)

    agwpe.disconnect()


def handle_version(major, minor):
    print("Version", major, minor)


time_last_packet_received_msec = 0
full_data = b''


def handle_raw_packet(data: bytes):
    try:
        # Try and decode to see if it's a pacpal message
        msg = decode_pacpal_message(data)
        print('New data received with length', len(data), 'bytes')
        global full_data
        full_data += msg
        current_crc32 = zlib.crc32(full_data) & 0xffffffff
        print('Total data is length', len(full_data), 'bytes, and has a crc32 of', current_crc32)

        global time_last_packet_received_msec
        time_last_packet_received_msec = round(time.time() * 1000)
    except Exception as e:
        print('Got raw packet, but failed to decode', e)


#   PACPAL     Magic
#   VERSION    0x01
#   CALLSIGN   10 bytes     Right padded with 0x00  (I think 7 is the longest, but people like SSID too so...)
#   TRANSFER#  16bit int    One transfer, multiple files  (random number probably fine)
#   FILE       8bit int     Which file are the blocks/data associated with.
#                           0 = metadata about transfer (names, comments, etc)
#   BLOCK      16bit int    Which block is the data for
#   MAX_BLOCK  16bit int    How many blocks in total
#                           This can't be in the metadata, because the metadata might be >1 block long
#   CRC32      32bit int
#   DATA       Bytes[]

# 38 byte header, eww......  I think we actually need to make sure it's at 36 bytes anyway for Direwolf to consider
# it a valid frame?


# 256 byte packets
# Msec taken 9149
# Bytes transferred 8192
# Speed 895.3984041971801 byte/s

# 512 byte packets
# Msec taken 7895
# Bytes transferred 8192
# Speed 1037.6187460417987 byte/s

# 1024 byte packets
# Msec taken 7841
# Bytes transferred 8192
# Speed 1044.7646983803086 byte/s

if __name__ == '__main__':
    recv_client = AgwpeClient()

    try:
        recv_client.connect('localhost', 8000)
        recv_client.enable_raw_monitoring()
        recv_client.on_raw_packet.append(handle_raw_packet)

        test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07' * 1024
        checksum = zlib.crc32(test_data) & 0xffffffff
        print('Data sent is', len(test_data), 'bytes long, and has a crc32 of', checksum)

        time_start_msec = round(time.time() * 1000)
        transfer_data('localhost', 9000, b'VK3ARD', test_data)

        time.sleep(8)

        transfer_time_msec = time_last_packet_received_msec - time_start_msec
        print('Msec taken', transfer_time_msec)
        print('Bytes transferred', len(full_data))
        print('Speed', len(full_data) / (transfer_time_msec/1000), 'byte/s')

    finally:
        recv_client.disconnect()
