import socket
import threading
import struct
import time


class SimpleTcpClient:
    """
    Stolen from mboukhlouf/tinytcp

    TODO: Shutdown flag

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

    def connect(self, host, port):
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((host, port))

    def start_read_loop(self):
        self._thread = threading.Thread(target=self._wait_for_data)
        self._thread.start()

    def stop(self):
        self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()

    def send(self, msg: bytes):
        self._socket.send(msg)


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


def handle_data(data: bytes):
    print("Received Data")
    print(AgwpePacket.decode(data))


print('Connecting...')
client = SimpleTcpClient()
client.on_data.append(handle_data)
client.connect('localhost', 8000)
client.start_read_loop()

print('Asking for Version Info...')
p = AgwpePacket()
p.set_kind('R')
# p.set_data(b"\x00" * 4)  # Beats me why
client.send(p.encode())
time.sleep(1)

print('Asking for Port Capabilities...')
p = AgwpePacket()
p.set_kind('g')
client.send(p.encode())
time.sleep(1)

print('Asking for Port Information...')
p = AgwpePacket()
p.set_kind('G')
client.send(p.encode())
time.sleep(1)

print('Turning on normal monitoring...')
p = AgwpePacket()
p.set_kind('m')
client.send(p.encode())

print('Sending UNPROTO AX.25 packet...')
p = AgwpePacket()
p.set_kind('M')
p.set_call_from('VK3ARD-15')
p.set_call_to('PACPAL')  # 6 characters!?  Is this a AX.25 limitation?
p.set_data(b"0123456789abcdef"*4)
client.send(p.encode())
time.sleep(1)

print('Waiting...')
time.sleep(1)

print('Stopping tcp connection...')
client.stop()
