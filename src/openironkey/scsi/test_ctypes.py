#!/usr/bin/env python3
"""
IronKey SCSI - Working ctypes-based implementation
"""

import os
import ctypes
import ctypes.util
import array
from typing import Tuple

# Load libc
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

# SG_IO ioctl number
SG_IO = 0x2285
SG_DXFER_NONE = 0
SG_DXFER_TO_DEV = 1
SG_DXFER_FROM_DEV = 2
SG_DXFER_TO_FROM_DEV = 3

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
          timeout: int = 5000) -> Tuple[int, bytes, bytes]:
    """Execute SG_IO command using ctypes"""
    
    cmdp = array.array('B', cdb)
    sbp = array.array('B', bytes(32))
    dxferp = array.array('B', data) if data else array.array('B', bytes(256))
    
    hdr = SG_IO_HDR()
    hdr.interface_id = ord('S')
    hdr.dxfer_direction = direction
    hdr.cmd_len = len(cdb)
    hdr.mx_sb_len = 32
    hdr.iovec_count = 0
    hdr.dxfer_len = len(dxferp) if direction != SG_DXFER_NONE else 0
    hdr.dxferp = ctypes.c_void_p(dxferp.buffer_info()[0]) if direction != SG_DXFER_NONE else 0
    hdr.cmdp = ctypes.c_void_p(cmdp.buffer_info()[0])
    hdr.sbp = ctypes.c_void_p(sbp.buffer_info()[0])
    hdr.timeout = timeout
    hdr.flags = 0
    hdr.pack_id = 0
    hdr.usr_ptr = 0
    
    # Execute ioctl
    result = libc.ioctl(fd, SG_IO, ctypes.byref(hdr))
    if result != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    
    status = hdr.status
    sense = bytes(sbp[:hdr.sb_len_wr])
    data_len = hdr.dxfer_len - hdr.resid
    result_data = bytes(dxferp[:data_len]) if data_len > 0 else b''
    
    return status, sense, result_data

# Test it
for i in range(5):
    path = f'/dev/sg{i}'
    if not os.path.exists(path):
        continue
    try:
        fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
        cdb = bytes([0x12, 0, 0, 0, 96, 0])
        status, sense, data = sg_io(fd, cdb, direction=SG_DXFER_FROM_DEV)
        if data:
            vendor = data[8:16].decode('ascii', errors='ignore').strip()
            product = data[16:32].decode('ascii', errors='ignore').strip()
            print(f'{path}: Vendor={vendor}, Product={product}, Status=0x{status:02x}')
        os.close(fd)
    except Exception as e:
        print(f'{path}: Error: {e}')