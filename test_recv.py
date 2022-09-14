import sys
import struct
import time
import zlib
from agwpe_client import AgwpeClient
from pacpal_message import PacpalMessage


time_first_packet_received_msec = 0
time_last_packet_received_msec = 0
full_data = b''


def handle_raw_packet(data: bytes):
    try:
        # Try and decode to see if it's a pacpal message
        msg = PacpalMessage.decode(data)
        print('New data received with length', len(data), 'bytes')
        global full_data
        full_data += msg
        current_crc32 = zlib.crc32(full_data) & 0xffffffff
        print('Total data is length', len(full_data), 'bytes, and has a crc32 of', current_crc32)

        global time_first_packet_received_msec
        if time_first_packet_received_msec == 0:
            time_first_packet_received_msec = round(time.time() * 1000)

        global time_last_packet_received_msec
        time_last_packet_received_msec = round(time.time() * 1000)
    except Exception as e:
        print('Got raw packet, but failed to decode', e)


if __name__ == '__main__':
    recv_client = AgwpeClient()

    try:
        recv_client.connect('localhost', 8000)
        recv_client.enable_raw_monitoring()
        recv_client.on_raw_packet.append(handle_raw_packet)

        while True:
            time.sleep(1)

    finally:
        recv_client.disconnect()

        transfer_time_msec = time_last_packet_received_msec - time_first_packet_received_msec
        print('Msec taken', transfer_time_msec)
        print('Bytes transferred', len(full_data))
        print('Speed', len(full_data) / (transfer_time_msec/1000), 'byte/s')


