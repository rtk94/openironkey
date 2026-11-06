#!/usr/bin/env python3
"""
USBpcap capture script for IronKey unlock traffic.
Run on WINDOWS as Administrator after installing USBPcap.
https://desowin.org/usbpcap/
"""
import subprocess
import sys
import os
from datetime import datetime

def find_ironkey():
    """Find IronKey USB device ID (VID:PID = 1953:0202)"""
    # USBPcap devices are listed as \\.\USBPcap1, \\.\USBPcap2, etc.
    # Each corresponds to a USB bus/device
    # Use Wireshark's tshark to list devices
    try:
        result = subprocess.run(
            ['tshark', '-D'],
            capture_output=True,
            text=True,
            timeout=10
        )
        print("Available USBPcap interfaces:")
        print(result.stdout)
        print("\nLook for IronKey (VID:PID 1953:0202) in the list.")
        print("Then run: usbpcapcmd -d <device> -o ironkey_unlock.pcapng")
    except FileNotFoundError:
        print("tshark not found. Install Wireshark with USBPcap support.")
        print("https://www.wireshark.org/download.html")
    except Exception as e:
        print(f"Error: {e}")

def capture_instructions():
    """Print step-by-step capture instructions."""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  IronKey USB Traffic Capture — Windows USBPcap                      ║
╚══════════════════════════════════════════════════════════════════════╝

PREREQUISITES:
  1. Install USBPcap: https://desowin.org/usbpcap/download.html
  2. Install Wireshark: https://www.wireshark.org/download.html
  3. Run as Administrator (PowerShell)

STEPS:
  1. Insert IronKey S200 (VID:PID 1953:0202)
  2. List capture devices:
     tshark -D
     (Look for interface with "IronKey" or note its number)

  3. Start capture (Terminal 1):
     usbpcapcmd -d \\.\\USBPcap1 -o ironkey_unlock.pcapng
     (Replace USBPcap1 with the correct interface from step 2)

  4. Run IronKey.exe unlock (Terminal 2 or manually):
     cd C:\\IronKey\\WINDOWS
     IronKey.exe
     (Enter PIN in GUI)

  5. Stop capture after unlock completes (Ctrl+C in Terminal 1)

  6. Copy the capture file to Linux:
     (USB drive, network share, etc.)
     ironkey_unlock.pcapng

  7. On Linux, parse the capture:
     python3 parse_usbpcap.py ironkey_unlock.pcapng

ANALYSIS:
  The Python parser will extract:
  • SCSI CDB commands (opcode 0x20 vendor commands)
  • Challenge-response pairs
  • PBKDF2 parameters (if visible in data phase)
  • Authentication sequence timing

WIRESHARK FILTERS (for manual analysis):
  usb.bus_id == 1 && usb.device_address == 5  (adjust bus/device)
  usb.endpoint_number != 0
  scsi.cmd.opcode == 0x20  (vendor-specific commands)

NOTES:
  • Capture BEFORE entering PIN — challenge generation is critical
  • Perform a COLD unlock (re-insert device) for clean trace
  • Capture includes full USB transactions (setup + data)
""")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'list':
        find_ironkey()
    elif len(sys.argv) > 1 and sys.argv[1] == 'help':
        capture_instructions()
    else:
        print("IronKey USBPcap Capture Tool")
        print("=" * 50)
        print()
        print("Usage:")
        print("  python capture_usbpcap.py           - Show instructions")
        print("  python capture_usbpcap.py list      - List devices (needs tshark)")
        print("  python capture_usbpcap.py help      - Detailed instructions")
        print()
        capture_instructions()

if __name__ == "__main__":
    main()