import threading
import struct
from agwpe_tcp_client import AgwpeTcpClient
from agwpe_packet import AgwpePacket


# Just to make sure all AgwpeClients call the events one-by-one
AgwpeClientMutex = threading.Lock()


class AgwpeClient:
    def __init__(self):
        self.tcp_client = AgwpeTcpClient()

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
