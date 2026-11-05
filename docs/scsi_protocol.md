#!/usr/bin/env python3
"""
IronKey S200 SCSI Protocol Reverse Engineering - Captured Commands

From strace analysis of the official Linux binary during unlock:

=== Device Discovery ===
- INQUIRY (0x12) on all SCSI generic devices
- Matches "IronKey" vendor string
- Uses /dev/sg3 (Secure Drive) for commands

=== Unlock Sequence (16-byte CDBs, opcode 0x20) ===

1. INIT CHALLENGE:
   CDB: 20 03 2c 00 00 00 00 00 00 00 00 00 00 00 00 00
   Dir: FROM_DEV, dxfer_len=14
   Response: 14 bytes (challenge data)

2. GET CHALLENGE RESPONSE:
   CDB: 20 03 2c 01 00 00 00 00 00 00 00 00 00 00 00 00
   Dir: FROM_DEV, dxfer_len=2
   Response: 2 bytes (status?)

3. INIT PIN ENTRY:
   CDB: 20 03 20 00 02 00 00 00 00 00 00 00 00 00 00 00
   Dir: FROM_DEV, dxfer_len=2
   Response: 2 bytes

4. NO-OP (sync):
   CDB: 20 03 20 03 00 00 00 00 00 00 00 00 00 00 00 00
   Dir: NONE, dxfer_len=0

5. READ KEY DATA 1:
   CDB: 20 00 f8 90 00 b6 2a 49 9f d0 a9 f3 9a 6a 70 c6
   Dir: FROM_DEV, dxfer_len=31
   Response: 31 bytes (encrypted key blob?)

6. READ KEY DATA 2:
   CDB: 20 00 06 91 99 d2 43 56 53 28 81 60 2f 80 18 eb
   Dir: FROM_DEV, dxfer_len=4
   Response: 4 bytes (checksum/IV?)

7. READ KEY DATA 3:
   CDB: 20 00 54 ce 5f e6 bc 2a f2 b8 06 33 c3 71 c0 de
   Dir: FROM_DEV, dxfer_len=128
   Response: 128 bytes (wrapped master key?)

8. READ DEVICE INFO:
   CDB: 20 08 8a a4 b0 69 9b 7a 6a a5 f5 67 ab 38 8e 4a
   Dir: FROM_DEV, dxfer_len=1024
   Response: 1024 bytes (device config, certs, etc.)

9. FINALIZE INIT:
   CDB: 20 03 2c 0a 00 00 00 00 00 00 00 00 00 00 00 00
   Dir: FROM_DEV, dxfer_len=2
   Response: 2 bytes (00 00 = success)

10. DECRYPT MASTER KEY:
    CDB: 20 00 d1 35 c1 ba 0b c7 41 75 84 fd c6 9d d6 55
    Dir: FROM_DEV, dxfer_len=270
    Response: 270 bytes (decrypted master key + metadata)

11. VERIFY/GET STATUS:
    CDB: 20 00 ff 83 d2 f3 fc 9a 05 c9 0d a2 ff 8f b9 bb
    Dir: FROM_DEV, dxfer_len=8
    Response: 8 bytes

12. WRITE UNLOCK STATE (FAILS with wrong PIN):
    CDB: 20 00 a9 27 4e 13 97 37 4f 99 cf ff 74 25 2a d8
    Dir: TO_DEV, dxfer_len=256
    Data: 256 bytes (PIN-derived unlock token)
    Result: CHECK CONDITION, Sense: F0 00 09 00 00 00 00 0B 00 00 00 00 98 0D 00 00
    Sense Key: 0x0B (ABORTED COMMAND), ASC/ASCQ: 0x980D (vendor specific)

=== Key Observations ===
- All commands use 16-byte CDB with opcode 0x20
- Byte 1 (sub-command): 0x03=init, 0x00=data, 0x08=large read
- Bytes 2-3: Command-specific parameters
- Bytes 4-15: 12-byte nonce/session ID (changes each unlock)
- The device maintains session state across commands
- PIN is never sent directly - used to derive unlock token locally
- Crypto operations happen on device (key unwrapping)

"""

# CDB Structure Analysis
# Byte 0: 0x20 (Vendor Specific)
# Byte 1: Sub-command (0x00, 0x03, 0x08)
# Byte 2: Command ID
# Byte 3: Flags/Options
# Bytes 4-15: 12-byte session nonce

# Known Command IDs (Byte 2):
# 0x2C: Init/Auth sequence
# 0x20: PIN/Key operations
# 0xF8, 0x06, 0x54, 0x8A: Read specific key slots
# 0xD1: Decrypt master key
# 0xFF: Status
# 0xA9: Write unlock state

# The 12-byte nonce appears to be generated per-session and used
# to derive encryption keys for the command channel

def analyze_captured_session():
    """Analyze the captured unlock session"""
    
    # Session 1 (first unlock attempt)
    nonce1 = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])  # First commands use zero nonce
    
    # Session 2 (after INIT)
    # From command 5: f8 90 00 b6 2a 49 9f d0 a9 f3 9a 6a
    # From command 6: 06 91 99 d2 43 56 53 28 81 60 2f 80
    # From command 7: 54 ce 5f e6 bc 2a f2 b8 06 33 c3 71
    # From command 8: 8a a4 b0 69 9b 7a 6a a5 f5 67 ab 38
    
    nonces = [
        bytes([0xf8, 0x90, 0x00, 0xb6, 0x2a, 0x49, 0x9f, 0xd0, 0xa9, 0xf3, 0x9a, 0x6a]),
        bytes([0x06, 0x91, 0x99, 0xd2, 0x43, 0x56, 0x53, 0x28, 0x81, 0x60, 0x2f, 0x80]),
        bytes([0x54, 0xce, 0x5f, 0xe6, 0xbc, 0x2a, 0xf2, 0xb8, 0x06, 0x33, 0xc3, 0x71]),
        bytes([0x8a, 0xa4, 0xb0, 0x69, 0x9b, 0x7a, 0x6a, 0xa5, 0xf5, 0x67, 0xab, 0x38]),
    ]
    
    # Command 10 nonce: d1 35 c1 ba 0b c7 41 75 84 fd c6 9d
    # Command 11 nonce: ff 83 d2 f3 fc 9a 05 c9 0d a2 ff 8f
    # Command 12 nonce: a9 27 4e 13 97 37 4f 99 cf ff 74 25
    
    return nonces

if __name__ == "__main__":
    print(__doc__)
    nonces = analyze_captured_session()
    print("\nCaptured nonces:")
    for i, n in enumerate(nonces):
        print(f"  [{i}] {n.hex()}")