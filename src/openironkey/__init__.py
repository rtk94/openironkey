#!/usr/bin/env python3
"""
IronKey S200 - Complete Linux Toolkit

Components:
1. SCSI Driver (ironkey_scsi.py) - Low-level device communication
2. PKCS#11 Module (ironkey_pkcs11.py) - Cryptoki implementation
3. CLI (ironkey_cli.py) - Command-line interface
4. Applet Launcher (ironkey_applet.py) - .ikp package manager
5. GUI (ironkey_gui.py) - Optional GTK interface
"""

# Version
__version__ = "1.0.0"
__author__ = "IronKey Linux Project"

# Exports
from .scsi.ironkey_scsi import (
    IronKeySCSI,
    IronKeySession,
    find_ironkey_device,
    sg_io,
    SG_IO_HDR,
    ScsiOp,
    IronKeySubCmd,
    IronKeyCmdId,
)

__all__ = [
    'IronKeySCSI',
    'IronKeySession', 
    'find_ironkey_device',
    'sg_io',
    'SG_IO_HDR',
    'ScsiOp',
    'IronKeySubCmd',
    'IronKeyCmdId',
]