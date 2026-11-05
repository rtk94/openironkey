#!/usr/bin/env python3
"""
IronKey S200 SCSI Driver - Fixed Session Management

The protocol uses dynamic nonces - each command's nonce is derived from previous responses.
"""

import os
import ctypes
import ctypes.util
import array
import hashlib
import secrets
import logging
from typing import Tuple, Dict, Optional, List
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger(__name__)

libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)

SG_IO = 0x2285
SG_DXFER_NONE = 0
SG_DXFER_TO_DEV = 1
SG_DXFER_FROM_DEV = 2
SG_DXFER_TO_FROM_DEV = 3

class ScsiOp(IntEnum):
    TEST_UNIT_READY = 0x00
    REQUEST_SENSE = 0x03
    INQUIRY = 0x12
    MODE_SENSE = 0x1A
    READ_CAPACITY = 0x25
    READ_10 = 0x28
    WRITE_10 = 0x2A

IRONKEY_VENDOR_OP = 0x20

class IronKeySubCmd(IntEnum):
    INIT_AUTH = 0x03
    DATA_OP = 0x00
    LARGE_READ = 0x08

class IronKeyCmdId(IntEnum):
    GET_CHALLENGE = 0x2C
    GET_CHALLENGE_RESP = 0x2C
    INIT_PIN = 0x20
    FINALIZE_INIT = 0x2C
    READ_KEY_SLOT_1 = 0xF8
    READ_KEY_SLOT_2 = 0x06
    READ_KEY_SLOT_3 = 0x54
    READ_DEVICE_INFO = 0x8A
    DECRYPT_MASTER_KEY = 0xD1
    GET_STATUS = 0xFF
    WRITE_UNLOCK = 0xA9

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
          timeout: int = 5000) -> Tuple[int, bytes, bytes]:
    
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

@dataclass
class IronKeySession:
    device_path: str
    fd: int = -1
    # Dynamic nonce - updated after each command
    current_nonce: bytes = field(default_factory=lambda: bytes(12))
    challenge: bytes = b''
    challenge_response: bytes = b''
    key_slots: Dict[int, bytes] = field(default_factory=dict)
    device_info: bytes = b''
    master_key: bytes = b''
    authenticated: bool = False
    step: int = 0
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, *args):
        self.close()
    
    def open(self):
        self.fd = os.open(self.device_path, os.O_RDWR | os.O_NONBLOCK)
        logger.info(f"Opened {self.device_path}")
        # Start with zero nonce
        self.current_nonce = bytes(12)
        self.step = 0
    
    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1
    
    def update_nonce(self, response: bytes):
        """Update nonce from response - use first 12 bytes of response"""
        if len(response) >= 12:
            self.current_nonce = response[:12]
            logger.debug(f"Updated nonce (step {self.step}): {self.current_nonce.hex()}")

class IronKeySCSI:
    def __init__(self, device_path: str):
        self.device_path = device_path
        self.session: Optional[IronKeySession] = None
    
    def __enter__(self):
        self.session = IronKeySession(self.device_path)
        self.session.__enter__()
        return self
    
    def __exit__(self, *args):
        if self.session:
            self.session.__exit__(*args)
    
    def _sg_io(self, cdb: bytes, data: bytes = b'', 
               direction: int = SG_DXFER_FROM_DEV,
               data_len: int = 0,
               timeout: int = 5000) -> Tuple[int, bytes, bytes]:
        if self.session is None or self.session.fd < 0:
            raise RuntimeError("Session not open")
        return sg_io(self.session.fd, cdb, data, direction, data_len, timeout)
    
    def inquiry(self) -> bytes:
        cdb = bytes([ScsiOp.INQUIRY, 0, 0, 0, 96, 0])
        status, sense, data = self._sg_io(cdb, data=bytes(96))
        if status != 0:
            raise RuntimeError(f"INQUIRY failed: status=0x{status:02x}, sense={sense.hex()}")
        return data
    
    def test_unit_ready(self) -> bool:
        cdb = bytes([ScsiOp.TEST_UNIT_READY] + [0]*5)
        status, sense, _ = self._sg_io(cdb)
        return status == 0
    
    def _vendor_cmd(self, sub_cmd: int, cmd_id: int, flags: int = 0,
                    data: bytes = b'', direction: int = SG_DXFER_FROM_DEV,
                    data_len: int = 0, timeout: int = 20000) -> bytes:
        if self.session is None:
            raise RuntimeError("No active session")
        
        cdb = bytearray(16)
        cdb[0] = IRONKEY_VENDOR_OP
        cdb[1] = sub_cmd
        cdb[2] = cmd_id
        cdb[3] = flags
        cdb[4:16] = self.session.current_nonce
        
        if data_len == 0:
            data_len = len(data) if direction == SG_DXFER_TO_DEV else 256
        
        status, sense, result = self._sg_io(bytes(cdb), data, direction, data_len, timeout)
        
        self.session.step += 1
        
        # Update nonce from successful responses
        if status == 0 and result:
            self.session.update_nonce(result)
        
        if status != 0 and status != 0x02:
            logger.warning(f"Vendor cmd 0x{sub_cmd:02x} 0x{cmd_id:02x} failed: "
                          f"status=0x{status:02x}, sense={sense.hex()}")
        
        return result
    
    def get_challenge(self) -> bytes:
        """Step 1: Get challenge (uses zero nonce)"""
        self.session.current_nonce = bytes(12)  # Reset to zero
        result = self._vendor_cmd(
            IronKeySubCmd.INIT_AUTH, IronKeyCmdId.GET_CHALLENGE,
            flags=0x00, data_len=14
        )
        self.session.challenge = result
        return result
    
    def get_challenge_response(self) -> bytes:
        """Step 2: Get challenge response (uses zero nonce)"""
        result = self._vendor_cmd(
            IronKeySubCmd.INIT_AUTH, IronKeyCmdId.GET_CHALLENGE_RESP,
            flags=0x01, data_len=2
        )
        self.session.challenge_response = result
        return result
    
    def init_pin_entry(self) -> bytes:
        """Step 3: Init PIN entry (uses zero nonce)"""
        result = self._vendor_cmd(
            IronKeySubCmd.INIT_AUTH, IronKeyCmdId.INIT_PIN,
            flags=0x00, data_len=2
        )
        return result
    
    def finalize_init(self) -> bytes:
        """Step 4: Finalize init (uses zero nonce)"""
        result = self._vendor_cmd(
            IronKeySubCmd.INIT_AUTH, IronKeyCmdId.FINALIZE_INIT,
            flags=0x0A, data_len=2
        )
        return result
    
    def read_key_slot(self, slot: int, length: int) -> bytes:
        cmd_map = {
            1: (IronKeySubCmd.DATA_OP, IronKeyCmdId.READ_KEY_SLOT_1),
            2: (IronKeySubCmd.DATA_OP, IronKeyCmdId.READ_KEY_SLOT_2),
            3: (IronKeySubCmd.DATA_OP, IronKeyCmdId.READ_KEY_SLOT_3),
        }
        if slot not in cmd_map:
            raise ValueError(f"Unknown key slot: {slot}")
        
        sub, cmd = cmd_map[slot]
        result = self._vendor_cmd(sub, cmd, data_len=length)
        self.session.key_slots[slot] = result
        return result
    
    def read_device_info(self) -> bytes:
        result = self._vendor_cmd(
            IronKeySubCmd.LARGE_READ, IronKeyCmdId.READ_DEVICE_INFO,
            data_len=1024
        )
        self.session.device_info = result
        return result
    
    def decrypt_master_key(self) -> bytes:
        result = self._vendor_cmd(
            IronKeySubCmd.DATA_OP, IronKeyCmdId.DECRYPT_MASTER_KEY,
            data_len=270
        )
        self.session.master_key = result
        return result
    
    def get_status(self) -> bytes:
        return self._vendor_cmd(
            IronKeySubCmd.DATA_OP, IronKeyCmdId.GET_STATUS,
            data_len=8
        )
    
    def write_unlock_token(self, token: bytes) -> Tuple[int, bytes, bytes]:
        if len(token) != 256:
            raise ValueError("Unlock token must be 256 bytes")
        
        cdb = bytearray(16)
        cdb[0] = IRONKEY_VENDOR_OP
        cdb[1] = IronKeySubCmd.DATA_OP
        cdb[2] = IronKeyCmdId.WRITE_UNLOCK
        cdb[3] = 0x00
        cdb[4:16] = self.session.current_nonce
        
        return self._sg_io(bytes(cdb), token, SG_DXFER_TO_DEV, 256, 20000)
    
    def unlock(self, pin: str) -> bool:
        logger.info("Starting unlock sequence...")
        
        challenge = self.get_challenge()
        logger.info(f"Challenge ({len(challenge)} bytes): {challenge.hex()}")
        
        resp = self.get_challenge_response()
        logger.info(f"Challenge response: {resp.hex()}")
        
        self.init_pin_entry()
        self.finalize_init()
        
        self.read_key_slot(1, 31)
        self.read_key_slot(2, 4)
        self.read_key_slot(3, 128)
        
        self.read_device_info()
        self.decrypt_master_key()
        
        unlock_token = self._derive_unlock_token(pin)
        
        status, sense, data = self.write_unlock_token(unlock_token)
        
        if status == 0:
            self.session.authenticated = True
            logger.info("Unlock successful!")
            return True
        else:
            logger.error(f"Unlock failed: status=0x{status:02x}, sense={sense.hex()}")
            return False
    
    def _derive_unlock_token(self, pin: str) -> bytes:
        pin_bytes = pin.encode('utf-16-le')
        salt = self.session.challenge + self.session.current_nonce
        return hashlib.pbkdf2_hmac('sha256', pin_bytes, salt, 10000, dklen=256)

def find_ironkey_device() -> Optional[str]:
    for i in range(32):
        path = f"/dev/sg{i}"
        if not os.path.exists(path):
            continue
        try:
            with IronKeySCSI(path) as dev:
                data = dev.inquiry()
                vendor = data[8:16].decode('ascii', errors='ignore').strip()
                product = data[16:32].decode('ascii', errors='ignore').strip()
                if 'IronKey' in vendor and 'Secure' in product:
                    return path
        except Exception:
            continue
    return None

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    
    print("Scanning for IronKey...")
    device = find_ironkey_device()
    
    if not device:
        print("No IronKey Secure Drive found")
        exit(1)
    
    print(f"Found IronKey at {device}")
    
    with IronKeySCSI(device) as dev:
        data = dev.inquiry()
        print(f"Vendor: {data[8:16].decode().strip()}")
        print(f"Product: {data[16:32].decode().strip()}")
        print(f"Revision: {data[32:36].decode().strip()}")
        
        print("\nAttempting unlock with test PIN...")
        success = dev.unlock("test123")
        print(f"Unlock result: {'SUCCESS' if success else 'FAILED (expected with wrong PIN)'}")