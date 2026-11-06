#!/usr/bin/env python3
"""
Parse USBPcap capture of IronKey unlock traffic.
Extracts SCSI vendor commands (opcode 0x20) and their data phases.

Usage:
    pip install pyshark
    python3 parse_usbpcap.py ironkey_unlock.pcapng

Or with scapy (no tshark needed):
    pip install scapy
    python3 parse_usbpcap.py --scapy ironkey_unlock.pcapng
"""
import sys
import os
import struct
from collections import defaultdict

# IronKey vendor command opcodes (from docs/scsi_protocol.md)
IRNONKEY_CMDS = {
    0x00: "NO_OP",
    0x01: "PROBE",
    0x02: "INIT_PIN",
    0x03: "GET_CHALLENGE",
    0x04: "VERIFY_CHALLENGE",
    0x05: "UNLOCK_TOKEN",
    0x06: "CRYPT_INIT",
    0x07: "CRYPT_OPERATION",
    0x08: "GET_STATUS",
    0x09: "KEY_EXPORT",  # hypothetical
    0x0A: "RANDOM_GEN",   # hypothetical
}

def parse_cdb(cdb_bytes):
    """Parse a 16-byte IronKey vendor CDB."""
    if len(cdb_bytes) < 16:
        return None
    
    opcode = cdb_bytes[0]
    if opcode != 0x20:
        return None
    
    # IronKey CDB format:
    # Byte 0: 0x20 (opcode)
    # Byte 1: control flags
    # Byte 2-3: command code (big-endian)
    # Byte 4: transfer length or param
    # Byte 5: subcommand
    # Bytes 6-15: reserved / additional params
    
    cmd_code = struct.unpack('>H', cdb_bytes[2:4])[0]
    subcmd = cdb_bytes[5] if len(cdb_bytes) > 5 else 0
    
    # Command name lookup
    cmd_name = IRNONKEY_CMDS.get(cmd_code, f"UNKNOWN_0x{cmd_code:04X}")
    
    return {
        'opcode': opcode,
        'cmd_code': cmd_code,
        'cmd_name': cmd_name,
        'subcmd': subcmd,
        'raw_cdb': cdb_bytes.hex(),
        'full_cdb': cdb_bytes,
    }

def parse_with_pyshark(pcap_file):
    """Parse using pyshark (requires tshark)."""
    try:
        import pyshark
    except ImportError:
        print("pyshark not installed. Run: pip install pyshark")
        print("Also requires tshark (Wireshark) in PATH.")
        return False
    
    print(f"Parsing {pcap_file} with pyshark...")
    print()
    
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter='usb.endpoint_number != 0'
    )
    
    scsi_commands = []
    data_phases = []
    
    for pkt in cap:
        # Look for SCSI commands in USB bulk transfers
        if hasattr(pkt, 'scsi') and hasattr(pkt.scsi, 'cmd'):
            cdb_raw = pkt.scsi.cmd if hasattr(pkt.scsi, 'cmd') else None
            if cdb_raw:
                cdb_bytes = bytes.fromhex(cdb_raw)
                parsed = parse_cdb(cdb_bytes)
                if parsed:
                    print(f"[{pkt.frame.number}] {parsed['cmd_name']} (0x{parsed['cmd_code']:04X})")
                    print(f"  CDB: {parsed['raw_cdb']}")
                    scsi_commands.append(parsed)
        
        # Look for data phases
        if hasattr(pkt, 'usb') and hasattr(pkt.usb, 'capdata'):
            data = pkt.usb.capdata
            if data and data != '':  # Non-empty data phase
                print(f"  Data: {data[:64]}...")  # First 64 chars
                data_phases.append(data)
    
    print()
    print(f"Found {len(scsi_commands)} IronKey SCSI commands")
    print(f"Found {len(data_phases)} data phases")
    
    return len(scsi_commands) > 0

def parse_with_scapy(pcap_file):
    """Parse using scapy (pure Python, no tshark needed)."""
    try:
        from scapy.all import rdpcap, USBPcapLinktype
        from scapy.layers.usb import USB
    except ImportError:
        print("scapy not installed. Run: pip install scapy")
        return False
    
    print(f"Parsing {pcap_file} with scapy...")
    print()
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        print("Note: scapy may need USBPcap linktype support.")
        return False
    
    print(f"Total packets: {len(packets)}")
    print()
    
    scsi_commands = []
    
    for i, pkt in enumerate(packets):
        # Scapy's USB layer parsing is limited
        # Look for raw SCSI CBW (Command Block Wrapper) signature
        if b'USBC' in bytes(pkt):
            # Found a CBW (Command Block Wrapper)
            idx = bytes(pkt).find(b'USBC')
            cbw_data = bytes(pkt)[idx:]
            
            if len(cbw_data) >= 31:  # CBW is 31 bytes minimum
                # CBW format: signature(4) + tag(4) + xfer_len(4) + flags(1) + LUN(1) + CB length(1) + CDB(16)
                cdb_start = idx + 15
                cdb_bytes = bytes(pkt)[cdb_start:cdb_start+16]
                
                if len(cdb_bytes) >= 16:
                    parsed = parse_cdb(cdb_bytes)
                    if parsed:
                        print(f"[Packet {i}] {parsed['cmd_name']} (0x{parsed['cmd_code']:04X})")
                        print(f"  CDB: {parsed['raw_cdb']}")
                        scsi_commands.append(parsed)
    
    print()
    print(f"Found {len(scsi_commands)} IronKey SCSI commands")
    
    return len(scsi_commands) > 0

def analyze_sequence(commands):
    """Analyze the command sequence for unlock patterns."""
    if not commands:
        return
    
    print("\n" + "=" * 60)
    print("UNLOCK SEQUENCE ANALYSIS")
    print("=" * 60)
    print()
    
    # Print sequence
    print("Command sequence:")
    for i, cmd in enumerate(commands):
        print(f"  {i:2d}. {cmd['cmd_name']} (0x{cmd['cmd_code']:04X})")
    
    print()
    print("Key observations:")
    
    # Find challenge-response pairs
    challenges = [c for c in commands if 'CHALLENGE' in c['cmd_name']]
    if challenges:
        print(f"  • Challenge commands: {len(challenges)}")
        for c in challenges:
            print(f"    - {c['cmd_name']}: subcmd={c['subcmd']}")
    
    # Find unlock token
    tokens = [c for c in commands if 'TOKEN' in c['cmd_name'] or 'UNLOCK' in c['cmd_name']]
    if tokens:
        print(f"  • Unlock/token commands: {len(tokens)}")
    
    # Find crypto operations
    crypto = [c for c in commands if 'CRYPT' in c['cmd_name']]
    if crypto:
        print(f"  • Crypto commands: {len(crypto)}")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 parse_usbpcap.py <pcapng_file>")
        print("  python3 parse_usbpcap.py --scapy <pcapng_file>")
        print()
        print("Requires: pip install pyshark  (or scapy for --scapy mode)")
        sys.exit(1)
    
    use_scapy = False
    pcap_file = None
    
    for arg in sys.argv[1:]:
        if arg == '--scapy':
            use_scapy = True
        elif not arg.startswith('-'):
            pcap_file = arg
    
    if not pcap_file:
        print("Error: No pcap file specified")
        sys.exit(1)
    
    if not os.path.exists(pcap_file):
        print(f"Error: File not found: {pcap_file}")
        sys.exit(1)
    
    print(f"File: {pcap_file}")
    print(f"Size: {os.path.getsize(pcap_file):,} bytes")
    print()
    
    success = False
    commands = []
    
    if use_scapy:
        success = parse_with_scapy(pcap_file)
    else:
        success = parse_with_pyshark(pcap_file)
    
    if not success:
        print("\nNo IronKey commands found in capture.")
        print("Possible reasons:")
        print("  - Capture started after unlock began")
        print("  - Wrong USB device captured")
        print("  - SCSI commands use different opcode")
        print("\nTry capturing again with a cold unlock (re-insert device).")

if __name__ == "__main__":
    main()