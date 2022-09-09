import socket
import threading
import struct
import time


class SimpleTcpClient:
    """
    Stolen from mboukhlouf/tinytcp

    I think this is too simple.  I actually need to parse headers and manually group frames raw data into AGWPE
    frames...  I'm not looking forward to that, it seems really complicated (how do I tell the difference between an
    incomplete header, and corrupted data?  How long do I wait for the rest of the data?).

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
            'data_len ' + repr(self.data_len),
            'data ' + repr(self.data),
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
        parts = struct.unpack("BBBBcBBB10s10sII" + str(data_len)+"s", raw)

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


class AgwpeClient:
    def __init__(self):
        self.tcp_client = SimpleTcpClient()

        self.on_version_info = []
        self.on_unknown_packet = []

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
            packet = AgwpePacket.decode(data)

            if packet.kind == b'R':  # version response
                (major, minor) = struct.unpack('HxxHxx', packet.data)  # this is wrong, or at least weird? 2005 127 ?
                self._trigger_event(self.on_version_info, major, minor)
            else:
                print(packet)
                self._trigger_event(self.on_unknown_packet, packet)

        except Exception as e:
            print("Unable to decode packet")
            print(e)
            print(repr(data))

    def request_version_info(self):
        packet = AgwpePacket()
        packet.set_kind('R')
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


def print_version(major, minor):
    print("Version", major, minor)


# SoundModem_HS 1
client1 = AgwpeClient()
client1.connect('localhost', 8000)
client1.on_version_info.append(print_version)
client1.request_version_info()
# client1.enable_raw_monitoring()

# SoundModem_HS 2
client2 = AgwpeClient()
client2.connect('localhost', 9000)
client2.on_version_info.append(print_version)
client2.enable_monitoring()
client2.enable_raw_monitoring()
client2.request_version_info()
# client2.register_callsign('VK3ARD')

time.sleep(1)

# Oh no.  The 'T' frames from monitored are missing unprintable bytes.  They are sent, but stripped.
# Spec says:  "containing the sent data in a fully transparent way (binary information,
#              no delimiters, bit stuffing or escape codes)"
#
# They are missing from 'U' frames too...
#
# Thankfully, the raw data 'K' frames have the binary data... But I now need to parse AX.25 headers too ugh


# But now I'm not getting U or K frames!?  WTF it was working before
# OMG, don't transmit from client1 and client2 at the same time and expect things to work!?
client1.send_unproto('CL1', 'PACPAL', b'Hello World 1 from 8000 \x00\x01\x02\x03\x04\x05\x06\x07 Where are my bytes!?')
client1.send_unproto('CL1', 'PACPAL', b'Hello World 2 from 8000 \x00\x01\x02\x03\x04\x05\x06\x07 Where are my bytes!?')
client1.send_unproto('CL1', 'PACPAL', b'Hello World 3 from 8000 \x00\x01\x02\x03\x04\x05\x06\x07 Where are my bytes!?')

time.sleep(1)

client2.send_unproto('CL2', 'PACPAL', b'Hello World 1 from 9000 \x00\x01\x02\x03\x04\x05\x06\x07 Where are my bytes!?')
client2.send_unproto('CL2', 'PACPAL', b'Hello World 2 from 9000 \x00\x01\x02\x03\x04\x05\x06\x07 Where are my bytes!?')
client2.send_unproto('CL2', 'PACPAL', b'Hello World 3 from 9000 \x00\x01\x02\x03\x04\x05\x06\x07 Where are my bytes!?')

time.sleep(1)

client1.disconnect()
client2.disconnect()

