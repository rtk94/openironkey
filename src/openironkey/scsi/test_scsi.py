#!/usr/bin/env python3
"""
IronKey SCSI test with proper struct packing
"""

import os
import struct
import fcntl
import array

SG_IO = 0x2285
SG_DXFER_FROM_DEV = 2

fd = os.open('/dev/sg3', os.O_RDWR | os.O_NONBLOCK)

# INQUIRY CDB
cdb = bytes([0x12, 0, 0, 0, 255, 0])
cmdp = array.array('B', cdb)
sbp = array.array('B', bytes(32))
dxferp = array.array('B', bytes(255))

# Build header manually with correct alignment
# Use 96 bytes to be safe
hdr = bytearray(96)

offset = 0
struct.pack_into('=iiBBHI', hdr, offset, ord('S'), SG_DXFER_FROM_DEV, len(cdb), 32, 0, 255)
offset += 4+4+1+1+2+4  # 16 bytes
offset += 6  # padding to 8-byte alignment = 22
struct.pack_into('QQQ', hdr, offset, dxferp.buffer_info()[0], cmdp.buffer_info()[0], sbp.buffer_info()[0])
offset += 24  # 46
struct.pack_into('IIII', hdr, offset, 5000, 0, 0, 0)
offset += 16  # 62
struct.pack_into('Q', hdr, offset, 0)  # usr_ptr
offset += 8  # 70
struct.pack_into('BBBBHHIII', hdr, offset, 0,0,0,0, 0,0, 0,0,0)
# 70 + 1+1+1+1+2+2+4+4+4 = 90

print(f"Header size: {len(hdr)}")

result = fcntl.ioctl(fd, SG_IO, hdr, True)

# Parse result
offset = 0
interface_id, dxfer_direction, cmd_len, mx_sb_len, iovec_count, dxfer_len = struct.unpack_from('=iiBBHI', result, offset)
offset += 16
offset += 6
dxferp_ptr, cmdp_ptr, sbp_ptr = struct.unpack_from('QQQ', result, offset)
offset += 24
timeout, flags, pack_id, usr_ptr = struct.unpack_from('IIII', result, offset)
offset += 16
offset += 8  # usr_ptr
status, masked_status, msg_status, sb_len_wr, host_status, driver_status, resid, duration, info = struct.unpack_from('BBBBHHIII', result, offset)

data = bytes(dxferp[:dxfer_len - resid]) if dxfer_len > resid else b''
print(f'Status: 0x{status:02x}')
print(f'Data len: {len(data)}')
print(f'Sense len: {sb_len_wr}')
if data:
    print(f'Vendor: {data[8:16].decode().strip()}')
    print(f'Product: {data[16:32].decode().strip()}')
    print(f'Revision: {data[32:36].decode().strip()}')

os.close(fd)