#!/usr/bin/env python3
"""
IronKey Applet Launcher - Extract and run .ikp packages

The .ikp files are ZIP archives containing portable Windows applications.
This module extracts them and launches the contained executables.
"""

import os
import sys
import zipfile
import tempfile
import shutil
import subprocess
import logging
from pathlib import Path
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Known applets on IronKey S200
KNOWN_APPLETS = {
    'CryptoCard': {
        'file': 'CryptoCard.ikp',
        'description': 'Core token management (token.exe, mpIK.dll, mpikcontrol.dll)',
        'main_exe': 'token.exe',
        'libs': ['mpIK.dll', 'mpikcontrol.dll', 'mpironkey.dll', 'mpbottom.dll'],
    },
    'IKOtpApp': {
        'file': 'IKOtpApp.ikp',
        'description': 'RSA SecurID token support',
        'main_exe': 'SecurID.exe',
        'libs': ['desktopclient.dll', 'ikrsaplugin.dll', 'libeay32.dll', 'ssleay32.dll', 
                 'QtCore4.dll', 'QtGui4.dll', 'QtNetwork4.dll', 'QtXml4.dll'],
    },
    'IKMalwareScanner': {
        'file': 'IKMalwareScanner.ikp',
        'description': 'McAfee malware scanner',
        'main_exe': 'IKMalwareScanner.exe',
        'libs': ['mcscan32.dll', 'mctool.exe', 'ikpkcs11.dll', 'libeay32.dll', 'ssleay32.dll',
                 'QtCore4.dll', 'QtGui4.dll', 'QtNetwork4.dll', 'QtXml4.dll'],
    },
    'IKSecureBackUp': {
        'file': 'IKSecureBackUp.ikp',
        'description': 'Network backup',
        'main_exe': 'iksecurebackup.exe',
        'libs': ['iknetservice.dll', 'ikp11helper.dll', 'libeay32.dll', 'ssleay32.dll', 'zlib1.dll'],
    },
    'MozillaFirefox': {
        'file': 'MozillaFirefox.ikp',
        'description': 'Portable Firefox with TorButton and SecureSessions',
        'main_exe': 'firefox.exe',
        'libs': ['xul.dll', 'mozjs.dll', 'nss3.dll', 'nspr4.dll', 'sqlite3.dll'],
    },
    'SecureSessions': {
        'file': 'SecureSessions.ikp',
        'description': 'Privoxy/Vidalia/Tor proxy bundle',
        'main_exe': 'vidalia.exe',
        'libs': ['libeay32.dll', 'ssleay32.dll', 'zlib1.dll'],
    },
}

@dataclass
class AppletInfo:
    name: str
    file: str
    description: str
    main_exe: str
    libs: List[str]
    extracted_path: Optional[str] = None
    manifest: Dict[str, Any] = field(default_factory=dict)

class IronKeyAppletManager:
    """Manage IronKey .ikp applets"""
    
    def __init__(self, mount_point: str = "/media/rich/IronKey"):
        self.mount_point = Path(mount_point)
        self.system_files_dir = self.mount_point / "WINDOWS" / "Ironkey-System-Files"
        self.temp_dirs: List[Path] = []
    
    def list_applets(self) -> List[AppletInfo]:
        """List all available applets"""
        applets = []
        for name, info in KNOWN_APPLETS.items():
            ikp_path = self.system_files_dir / info['file']
            if ikp_path.exists():
                applets.append(AppletInfo(
                    name=name,
                    file=info['file'],
                    description=info['description'],
                    main_exe=info['main_exe'],
                    libs=info['libs'],
                ))
        return applets
    
    def extract_applet(self, applet_name: str, dest_dir: Optional[Path] = None) -> Path:
        """Extract an applet to a temporary directory"""
        if applet_name not in KNOWN_APPLETS:
            raise ValueError(f"Unknown applet: {applet_name}")
        
        info = KNOWN_APPLETS[applet_name]
        ikp_path = self.system_files_dir / info['file']
        
        if not ikp_path.exists():
            raise FileNotFoundError(f"Applet file not found: {ikp_path}")
        
        if dest_dir is None:
            dest_dir = Path(tempfile.mkdtemp(prefix=f"ironkey_{applet_name}_"))
            self.temp_dirs.append(dest_dir)
        
        logger.info(f"Extracting {applet_name} to {dest_dir}")
        
        with zipfile.ZipFile(ikp_path, 'r') as zf:
            zf.extractall(dest_dir)
        
        return dest_dir
    
    def launch_applet(self, applet_name: str, args: List[str] = None, 
                      env: Dict[str, str] = None) -> subprocess.Popen:
        """Extract and launch an applet"""
        if applet_name not in KNOWN_APPLETS:
            raise ValueError(f"Unknown applet: {applet_name}")
        
        info = KNOWN_APPLETS[applet_name]
        extract_dir = self.extract_applet(applet_name)
        
        # Find the main executable
        exe_path = extract_dir / info['main_exe']
        if not exe_path.exists():
            # Search recursively
            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    if f.lower() == info['main_exe'].lower():
                        exe_path = Path(root) / f
                        break
        
        if not exe_path.exists():
            raise FileNotFoundError(f"Main executable not found: {info['main_exe']}")
        
        # Set up environment for Wine
        launch_env = os.environ.copy()
        if env:
            launch_env.update(env)
        
        # Add library path
        wine_lib_path = str(extract_dir)
        launch_env['WINEPATH'] = wine_lib_path + ':' + launch_env.get('WINEPATH', '')
        
        # Prepare command
        cmd = ['wine', str(exe_path)]
        if args:
            cmd.extend(args)
        
        logger.info(f"Launching: {' '.join(cmd)}")
        
        try:
            proc = subprocess.Popen(cmd, env=launch_env, cwd=str(extract_dir))
            return proc
        except FileNotFoundError:
            raise RuntimeError("Wine not installed. Install wine32:i386 to run Windows applets.")
    
    def cleanup(self):
        """Clean up temporary directories"""
        for d in self.temp_dirs:
            try:
                shutil.rmtree(d)
                logger.info(f"Cleaned up {d}")
            except Exception as e:
                logger.warning(f"Failed to clean up {d}: {e}")
        self.temp_dirs.clear()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.cleanup()


def main():
    """CLI for applet management"""
    import argparse
    
    parser = argparse.ArgumentParser(description="IronKey Applet Launcher")
    parser.add_argument('--mount', default="/media/rich/IronKey", help="IronKey mount point")
    parser.add_argument('--list', action='store_true', help="List available applets")
    parser.add_argument('--extract', metavar='NAME', help="Extract applet to temp dir")
    parser.add_argument('--launch', metavar='NAME', help="Launch applet")
    parser.add_argument('--args', nargs='*', default=[], help="Arguments for launched applet")
    parser.add_argument('--verbose', '-v', action='store_true')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    
    manager = IronKeyAppletManager(args.mount)
    
    try:
        if args.list:
            applets = manager.list_applets()
            print("Available applets:")
            for app in applets:
                print(f"  {app.name} ({app.file}): {app.description}")
        
        elif args.extract:
            dest = manager.extract_applet(args.extract)
            print(f"Extracted to: {dest}")
        
        elif args.launch:
            proc = manager.launch_applet(args.launch, args.args)
            print(f"Launched {args.launch} (PID: {proc.pid})")
            proc.wait()
            print(f"Exit code: {proc.returncode}")
        
        else:
            parser.print_help()
    
    finally:
        manager.cleanup()


if __name__ == "__main__":
    main()