#!/usr/bin/env python3
"""
Debug IronKey command sequence step by step
"""

import os
import ctypes
import ctypes.util
import array
import logging

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
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
          timeout: int = 5000) -> tuple:
    
    cmdp = array.array('B', cdb)
    sbp = array.array('B', bytes(32))
    
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
    hdr.mx_sb_len = 32
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

# Test exact strace sequence
fd = os.open('/dev/sg3', os.O_RDWR | os.O_NONBLOCK)

# Step 1: INQUIRY
cdb = bytes([0x12, 0, 0, 0, 96, 0])
status, sense, data = sg_io(fd, cdb, data=bytes(96))
print(f"INQUIRY: status=0x{status:02x}")

# Step 2: GET_CHALLENGE (matching strace exactly)
cdb = bytes([0x20, 0x03, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
status, sense, data = sg_io(fd, cdb, data_len=14, direction=SG_DXFER_FROM_DEV)
print(f"GET_CHALLENGE: status=0x{status:02x}, sense={sense.hex()}, data={data.hex()}")

# Step 3: GET_CHALLENGE_RESP (matching strace exactly - same zero nonce, dxfer_len=2)
cdb = bytes([0x20, 0x03, 0x2c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
status, sense, data = sg_io(fd, cdb, data_len=2, direction=SG_DXFER_FROM_DEV)
print(f"GET_CHALLENGE_RESP: status=0x{status:02x}, sense={sense.hex()}, data={data.hex()}")

# Step 4: INIT_PIN (strace: 20 03 20 00 02 00 00 00 00 00 00 00 00 00 00 00, dxfer_len=2)
cdb = bytes([0x20, 0x03, 0x20, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
status, sense, data = sg_io(fd, cdb, data_len=2, direction=SG_DXFER_FROM_DEV)
print(f"INIT_PIN: status=0x{status:02x}, sense={sense.hex()}, data={data.hex()}")

# Step 5: NO-OP (strace: 20 03 20 03 00 00 00 00 00 00 00 00 00 00 00 00, dxfer_len=0)
cdb = bytes([0x20, 0x03, 0x20, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
status, sense, data = sg_io(fd, cdb, direction=SG_DXFER_NONE, timeout=20000)
print(f"NO-OP: status=0x{status:02x}, sense={sense.hex()}, data={data.hex()}")

# Step 6: READ_KEY_SLOT_1 (strace: 20 00 f8 90 00 b6 2a 49 9f d0 a9 f3 9a 6a 70 c6, dxfer_len=31)
# Note: The nonce here comes from previous response! But strace shows it's different.
# Let's use the challenge response as nonce
challenge_nonce = bytes([0x50, 0x00, 0x0d, 0x02, 0x07, 0x01, 0x09, 0x50, 0x02, 0x17, 0x15, 0x2d])  # first 12 bytes
cdb = bytes([0x20, 0x00, 0xf8, 0x90]) + challenge_nonce
status, sense, data = sg_io(fd, cdb, data_len=31, direction=SG_DXFER_FROM_DEV, timeout=20000)
print(f"READ_KEY_SLOT_1: status=0x{status:02x}, sense={sense.hex()}, data_len={len(data)}")

os.close(fd)