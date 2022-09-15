import time
import zlib
from agwpe_client import AgwpeClient
from pacpal_message import PacpalMessage


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

        agwpe.send_raw_packet(PacpalMessage.encode(callsign, d))
        agwpe.request_outstanding_frames()
        time.sleep(0.1)

    agwpe.disconnect()


if __name__ == '__main__':

    # test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07' * 128  # 1KB
    test_data = b'\x00\x01\x02\x03\x04\x05\x06\x07' * 1024  # 8 KB

    checksum = zlib.crc32(test_data) & 0xffffffff
    print('Data to send is', len(test_data), 'bytes long, and has a crc32 of', checksum)

    time_start_msec = round(time.time() * 1000)
    transfer_data('localhost', 9000, b'VK3ARD', test_data)

    print('Done. All data queued.')
