import socket
import threading


class AgwpeTcpClient:
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
        # print('Sending', len(msg), 'bytes:', repr(msg))
        self._socket.sendall(msg)
