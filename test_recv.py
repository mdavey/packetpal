import time
import zlib
from agwpe_client import AgwpeClient
from pacpal_message import PacpalMessage


class ReceiveMessages:
    def __init__(self, host: str, port: int):
        self.client = AgwpeClient()
        self.client.connect(host, port)

        self.client.on_raw_packet.append(self.handle_raw_packet)
        self.client.enable_raw_monitoring()

        self.current_data = b''
        self.current_data_time_first_packet = 0
        self.current_data_time_last_packet = 0

    def start(self):
        while True:
            time.sleep(1)
            # Not already reset, and 8 seconds has passed since last data
            if self.current_data_time_last_packet != 0 and \
               self.current_msec() > self.current_data_time_last_packet + (1000*8):

                self.print_stats()
                self.reset_stats()

    def stop(self):
        self.client.disconnect()

    def reset_stats(self):
        self.current_data = b''
        self.current_data_time_first_packet = 0
        self.current_data_time_last_packet = 0

    def print_stats(self):
        transfer_time_msec = self.current_data_time_last_packet-self.current_data_time_first_packet
        print('Msec taken', transfer_time_msec)
        print('Bytes transferred', len(self.current_data))
        print('Speed', len(self.current_data) / (transfer_time_msec/1000), 'byte/s')

    @staticmethod
    def current_msec():
        return round(time.time()*1000)

    def handle_raw_packet(self, data: bytes):
        try:
            # Try and decode to see if it's a pacpal message
            msg = PacpalMessage.decode(data)
            print('New data received with length', len(data), 'bytes')

            self.current_data += msg
            current_crc32 = zlib.crc32(self.current_data) & 0xffffffff
            print('Total data is length', len(self.current_data), 'bytes, and has a crc32 of', current_crc32)

            if self.current_data_time_first_packet == 0:
                self.current_data_time_first_packet = self.current_msec()

            self.current_data_time_last_packet = self.current_msec()

        except Exception as e:
            print('Got raw packet, but failed to decode', e)


if __name__ == '__main__':

    recv = ReceiveMessages('localhost', 8000)
    print('Waiting for data...')
    
    try:
        recv.start()
    finally:
        recv.stop()
