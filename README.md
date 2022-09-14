# PacketPal

A Python experiment with packet modems using AGWPE.

Maybe good enough to get an idea how to use AGWPE.

## Requirements

- Direwolf 1.7.0 with my patch to enable flow control from non AX.25 packets
- Python 3.x

### Direwolf 1.7.0 patch

By default, when sending a 'y' AWGPE packet Direwolf only counts queues data that is a valid AX.25.  Because we're 
sending raw packets, Direwolf always returns 0 packets queued.

For testing I've modified line 987 of `src/tq.c`:

```text
    From: if (ax25_get_num_addr(pp) >= AX25_MIN_ADDRS) {
    
    To:   if (TRUE || ax25_get_num_addr(pp) >= AX25_MIN_ADDRS) {
```

I'm sure it breaks the source and dest filtering.  For now, I'm just seeing if this entire idea will work, later on I 
can talk to the Direwolf devs about it.

## Usage

For local testing, need one modem for receiving and one for sending.  For testing, I'm using SoundModem_HS by UZ7HO for 
receiving and Direwolf for sending.

Set the AGWPE ports in `test_recv.py` and `test_send.py`

Run `test_recv.py` in one console, and `test_send.py` in another.

When the data is all received, ctrl+c `test_recv.py` to see speed/etc 

## Notes

Potential message protocol

```
  PACPAL     Magic
  VERSION    0x01
  CALLSIGN   10 bytes     Right padded with 0x00  (I think 7 is the longest, but people like SSID too so...)
  TRANSFER#  16bit int    One transfer, multiple files  (random number probably fine)
  FILE       8bit int     Which file are the blocks/data associated with.
                          0 = metadata about transfer (names, comments, etc)
  BLOCK      16bit int    Which block is the data for
  MAX_BLOCK  16bit int    How many blocks in total
                          This can't be in the metadata, because the metadata might be >1 block long
  CRC32      32bit int
  DATA       Bytes[]
```

38 byte header, eww......  I think we actually need to make sure it's at 36 bytes anyway for Direwolf to consider
it a valid frame?

```text
256 byte messages
Msec taken 9149
Bytes transferred 8192
Speed 895.3984041971801 byte/s

512 byte messages
Msec taken 7895
Bytes transferred 8192
Speed 1037.6187460417987 byte/s

1024 byte messages
Msec taken 7841
Bytes transferred 8192
Speed 1044.7646983803086 byte/s
```

Hmm, if you ignore the startup and setup times it's actually even better.  Though maybe I've stopped counting the time the first message takes to transfer, so it's 10% slower?
```text
256 byte messages
Msec taken 7399
Bytes transferred 8192
Speed 1107.1766454926342 byte/s

512 byte messages
Msec taken 6760
Bytes transferred 8192
Speed 1211.8343195266273 byte/s

1024 byte messages
Msec taken 6161
Bytes transferred 8192
Speed 1329.6542769031003 byte/s
```