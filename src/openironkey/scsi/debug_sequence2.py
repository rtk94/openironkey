#!/usr/bin/env python3
"""
Debug IronKey command sequence with mx_sb_len=16
"""

import os
import ctypes
import ctypes.util
import array
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

SG_IO = 0x2285
SG_DXFER_TO_DEV = 1
SG_DXFER_FROM_DEV = 2
SG_DXFER_NONE = 0

class SG_IO_HDR(ctypes.Structure):
    _fields_ = [
        ('interface_id', ctypes.c_int),
        ('dxfer_direction', ctypes.c_int),
        ('cmd_len', ctypes.c_ubyte),
        ('mx_sb_len', ctypes.c_ubyte),
        ('iovec_count', ctypes.c_ushort),
        ('dxfer_len', ctypes.c_uint),
        ('dxferp', ctypes.c_void_p),
        ('cmdp', ctypes.c_void_p),
        ('sbp', ctypes.c_void_p),
        ('timeout', ctypes.c_uint),
        ('flags', ctypes.c_uint),
        ('pack_id', ctypes.c_int),
        ('usr_ptr', ctypes.c_void_p),
        ('status', ctypes.c_ubyte),
        ('masked_status', ctypes.c_ubyte),
        ('msg_status', ctypes.c_ubyte),
        ('sb_len_wr', ctypes.c_ubyte),
        ('host_status', ctypes.c_ushort),
        ('driver_status', ctypes.c_ushort),
        ('resid', ctypes.c_int),
        ('duration', ctypes.c_uint),
        ('info', ctypes.c_uint),
    ]

def sg_io(fd: int, cdb: bytes, data: bytes = b'', 
          direction: int = SG_DXFER_FROM_DEV,
          data_len: int = 0,
          timeout: int = 5000,
          mx_sb_len: int = 16) -> tuple:
    
    cmdp = array.array('B', cdb)
    sbp = array.array('B', bytes(mx_sb_len))
    
    if direction == SG_DXFER_NONE:
        buf_size = 0
    elif direction == SG_DXFER_TO_DEV:
        buf_size = len(data)
    else:
        buf_size = data_len if data_len > 0 else len(data) if data else 256
    
    dxferp = array.array('B', data) if data else array.array('B', bytes(buf_size))
    
    hdr = SG_IO_HDR()
    hdr.interface_id = ord('S')
    hdr.dxfer_direction = direction
    hdr.cmd_len = len(cdb)
    hdr.mx_sb_len = mx_sb_len
    hdr.iovec_count = 0
    hdr.dxfer_len = buf_size
    hdr.dxferp = ctypes.c_void_p(dxferp.buffer_info()[0]) if buf_size > 0 else 0
    hdr.cmdp = ctypes.c_void_p(cmdp.buffer_info()[0])
    hdr.sbp = ctypes.c_void_p(sbp.buffer_info()[0])
    hdr.timeout = timeout
    hdr.flags = 0
    hdr.pack_id = 0
    hdr.usr_ptr = 0
    
    result = libc.ioctl(fd, SG_IO, ctypes.byref(hdr))
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    
    status = hdr.status
    sense = bytes(sbp[:hdr.sb_len_wr])
    data_len = hdr.dxfer_len - hdr.resid
    result_data = bytes(dxferp[:data_len]) if data_len > 0 else b''
    
    return status, sense, result_data

fd = os.open('/dev/sg3', os.O_RDWR | os.O_NONBLOCK)

# Step 1: INQUIRY
cdb = bytes([0x12, 0, 0, 0, 96, 0])
status, sense, data = sg_io(fd, cdb, data=bytes(96), mx_sb_len=16)
print(f"INQUIRY: status=0x{status:02x}")

# Step 2: GET_CHALLENGE
cdb = bytes([0x20, 0x03, 0x2c, 0x00] + [0]*12)
status, sense, data = sg_io(fd, cdb, data_len=14, direction=SG_DXFER_FROM_DEV, mx_sb_len=16)
print(f"GET_CHALLENGE: status=0x{status:02x}, data={data.hex()}")

# Step 3: GET_CHALLENGE_RESP
cdb = bytes([0x20, 0x03, 0x2c, 0x01] + [0]*12)
status, sense, data = sg_io(fd, cdb, data_len=2, direction=SG_DXFER_FROM_DEV, mx_sb_len=16)
print(f"GET_CHALLENGE_RESP: status=0x{status:02x}, data={data.hex()}")

# Step 4: INIT_PIN
cdb = bytes([0x20, 0x03, 0x20, 0x00, 0x02] + [0]*11)
status, sense, data = sg_io(fd, cdb, data_len=2, direction=SG_DXFER_FROM_DEV, mx_sb_len=16)
print(f"INIT_PIN: status=0x{status:02x}, data={data.hex()}")

# Step 5: NO-OP (strace uses mx_sb_len=16, dxfer_len=0, SG_DXFER_NONE)
cdb = bytes([0x20, 0x03, 0x20, 0x03] + [0]*12)
status, sense, data = sg_io(fd, cdb, direction=SG_DXFER_NONE, timeout=20000, mx_sb_len=16)
print(f"NO-OP: status=0x{status:02x}, sense={sense.hex()}, data={data.hex()}")

# Step 6: READ_KEY_SLOT_1 - use the exact nonce from strace
# strace: 20 00 f8 90 00 b6 2a 49 9f d0 a9 f3 9a 6a 70 c6
cdb = bytes([0x20, 0x00, 0xf8, 0x90, 0x00, 0xb6, 0x2a, 0x49, 0x9f, 0xd0, 0xa9, 0xf3, 0x9a, 0x6a, 0x70, 0xc6])
status, sense, data = sg_io(fd, cdb, data_len=31, direction=SG_DXFER_FROM_DEV, timeout=20000, mx_sb_len=16)
print(f"READ_KEY_SLOT_1: status=0x{status:02x}, sense={sense.hex()}, data_len={len(data)}, data={data.hex() if data else 'empty'}")

# Step 7: READ_KEY_SLOT_2 - strace: 20 00 06 91 99 d2 43 56 53 28 81 60 2f 80 18 eb
cdb = bytes([0x20, 0x00, 0x06, 0x91, 0x99, 0xd2, 0x43, 0x56, 0x53, 0x28, 0x81, 0x60, 0x2f, 0x80, 0x18, 0xeb])
status, sense, data = sg_io(fd, cdb, data_len=4, direction=SG_DXFER_FROM_DEV, timeout=20000, mx_sb_len=16)
print(f"READ_KEY_SLOT_2: status=0x{status:02x}, sense={sense.hex()}, data={data.hex() if data else 'empty'}")

# Step 8: READ_KEY_SLOT_3 - strace: 20 00 54 ce 5f e6 bc 2a f2 b8 06 33 c3 71 c0 de
cdb = bytes([0x20, 0x00, 0x54, 0xce, 0x5f, 0xe6, 0xbc, 0x2a, 0xf2, 0xb8, 0x06, 0x33, 0xc3, 0x71, 0xc0, 0xde])
status, sense, data = sg_io(fd, cdb, data_len=128, direction=SG_DXFER_FROM_DEV, timeout=20000, mx_sb_len=16)
print(f"READ_KEY_SLOT_3: status=0x{status:02x}, sense={sense.hex()}, data_len={len(data)}")

# Step 9: READ_DEVICE_INFO - strace: 20 08 8a a4 b0 69 9b 7a 6a a5 f5 67 ab 38 8e 4a
cdb = bytes([0x20, 0x08, 0x8a, 0xa4, 0xb0, 0x69, 0x9b, 0x7a, 0x6a, 0xa5, 0xf5, 0x67, 0xab, 0x38, 0x8e, 0x4a])
status, sense, data = sg_io(fd, cdb, data_len=1024, direction=SG_DXFER_FROM_DEV, timeout=20000, mx_sb_len=16)
print(f"READ_DEVICE_INFO: status=0x{status:02x}, sense={sense.hex()}, data_len={len(data)}")

os.close(fd)