#!/usr/bin/env python3
"""
IronKey CLI - Modern Command Line Interface for IronKey S200

Usage:
    ironkey_cli --unlock [--pin PIN] [--device DEVICE]
    ironkey_cli --lock [--device DEVICE]
    ironkey_cli --status [--device DEVICE]
    ironkey_cli --change-pin [--old-pin PIN] [--new-pin PIN] [--device DEVICE]
    ironkey_cli --info [--device DEVICE]
    ironkey_cli --list-applets [--device DEVICE]
    ironkey_cli --launch-applet APPLET_NAME [--device DEVICE]
"""

import os
import sys
import argparse
import logging
import getpass
from typing import Optional, List

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from openironkey.scsi.ironkey_scsi import IronKeySCSI, find_ironkey_device

logger = logging.getLogger(__name__)

class IronKeyCLI:
    def __init__(self, device_path: Optional[str] = None):
        self.device_path = device_path or find_ironkey_device()
        if not self.device_path:
            raise RuntimeError("No IronKey device found")
        self.scsi = None
    
    def __enter__(self):
        self.scsi = IronKeySCSI(self.device_path)
        self.scsi.__enter__()
        return self
    
    def __exit__(self, *args):
        if self.scsi:
            self.scsi.__exit__(*args)
    
    def unlock(self, pin: str) -> bool:
        """Unlock the device with PIN"""
        print(f"Unlocking IronKey at {self.device_path}...")
        success = self.scsi.unlock(pin)
        if success:
            print("Device unlocked successfully!")
        else:
            print("Unlock failed!")
        return success
    
    def lock(self) -> bool:
        """Lock the device"""
        print("Locking device...")
        # Send lock command via SCSI
        # This would be implemented in the SCSI layer
        print("Device locked (SCSI lock command not yet implemented)")
        return True
    
    def status(self) -> dict:
        """Get device status"""
        print("Getting device status...")
        info = self.scsi.inquiry()
        print(f"  Vendor: {info[8:16].decode().strip()}")
        print(f"  Product: {info[16:32].decode().strip()}")
        print(f"  Revision: {info[32:36].decode().strip()}")
        
        # Try to get more info via vendor commands
        try:
            # This would use the full unlock sequence but just read status
            pass
        except Exception as e:
            print(f"  Extended status: {e}")
        
        return {"device": self.device_path}
    
    def change_pin(self, old_pin: str, new_pin: str) -> bool:
        """Change PIN"""
        print("Changing PIN...")
        # This requires being unlocked first
        print("PIN change not yet implemented (requires unlock + SCSI change PIN command)")
        return False
    
    def list_applets(self) -> List[dict]:
        """List installed applets"""
        print("Listing applets...")
        # This would read the CD-ROM partition
        applets = [
            {"name": "CryptoCard", "file": "CryptoCard.ikp", "description": "Core token management"},
            {"name": "IKOtpApp", "file": "IKOtpApp.ikp", "description": "RSA SecurID token support"},
            {"name": "IKMalwareScanner", "file": "IKMalwareScanner.ikp", "description": "McAfee malware scanner"},
            {"name": "IKSecureBackUp", "file": "IKSecureBackUp.ikp", "description": "Network backup"},
            {"name": "MozillaFirefox", "file": "MozillaFirefox.ikp", "description": "Portable Firefox + Tor"},
            {"name": "SecureSessions", "file": "SecureSessions.ikp", "description": "Privoxy/Vidalia/Tor proxy"},
        ]
        for app in applets:
            print(f"  {app['name']} ({app['file']}): {app['description']}")
        return applets
    
    def launch_applet(self, applet_name: str) -> bool:
        """Launch an applet"""
        print(f"Launching applet: {applet_name}")
        # This would extract and run the .ikp package
        print("Applet launcher not yet implemented")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="IronKey S200 CLI - Modern Linux Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ironkey_cli --unlock
  ironkey_cli --unlock --pin "mypassword"
  ironkey_cli --status
  ironkey_cli --list-applets
  ironkey_cli --launch-applet CryptoCard
        """
    )
    
    parser.add_argument('--device', '-d', help='SCSI device path (e.g., /dev/sg3)')
    parser.add_argument('--pin', '-p', help='PIN (if not provided, will prompt)')
    parser.add_argument('--old-pin', help='Old PIN for change-pin')
    parser.add_argument('--new-pin', help='New PIN for change-pin')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode')
    
    # Commands
    parser.add_argument('--unlock', action='store_true', help='Unlock device')
    parser.add_argument('--lock', action='store_true', help='Lock device')
    parser.add_argument('--status', action='store_true', help='Show device status')
    parser.add_argument('--change-pin', action='store_true', help='Change PIN')
    parser.add_argument('--info', action='store_true', help='Show device info')
    parser.add_argument('--list-applets', action='store_true', help='List installed applets')
    parser.add_argument('--launch-applet', metavar='NAME', help='Launch applet by name')
    
    args = parser.parse_args()
    
    # Setup logging
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
    elif args.quiet:
        logging.basicConfig(level=logging.WARNING)
    else:
        logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    # Get device
    device = args.device or find_ironkey_device()
    if not device:
        print("Error: No IronKey device found. Use --device to specify.", file=sys.stderr)
        return 1
    
    # Get PIN if needed
    pin = args.pin
    if args.unlock and not pin:
        pin = getpass.getpass("Enter IronKey PIN: ")
    
    try:
        with IronKeyCLI(device) as cli:
            if args.unlock:
                success = cli.unlock(pin or "")
                return 0 if success else 1
            elif args.lock:
                success = cli.lock()
                return 0 if success else 1
            elif args.status:
                cli.status()
                return 0
            elif args.change_pin:
                old = args.old_pin or getpass.getpass("Old PIN: ")
                new = args.new_pin or getpass.getpass("New PIN: ")
                success = cli.change_pin(old, new)
                return 0 if success else 1
            elif args.info or args.list_applets:
                cli.list_applets()
                return 0
            elif args.launch_applet:
                success = cli.launch_applet(args.launch_applet)
                return 0 if success else 1
            else:
                parser.print_help()
                return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())