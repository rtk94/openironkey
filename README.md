# OpenIronKey

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Development Status](https://img.shields.io/badge/status-alpha-orange.svg)](https://github.com/yourusername/openironkey)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)

A modern, open-source Linux toolkit for the **IronKey S200** secure USB drive.

## Overview

The IronKey S200 is a hardware-encrypted USB drive (circa 2013) featuring:
- **Hardware AES-256 encryption**
- **PKCS#11 cryptographic token interface** 
- **Secure password management**
- **Portable applets** (Firefox + Tor, RSA SecurID, malware scanner, encrypted backup)
- **Cross-platform support** (Windows, macOS, Linux)

**The Problem**: Official Linux support is 32-bit only, statically linked to OpenSSL 0.9.8 (EOL 2015), and lacks modern features.

**The Solution**: This toolkit provides native 64-bit Linux support with:
| Component | Description |
|-----------|-------------|
| 🔧 **SCSI Driver** | Clean 64-bit Python implementation using `sg_io` |
| 🔐 **PKCS#11 Module** | Full Cryptoki API (slots, tokens, sessions, crypto ops) |
| 💻 **CLI Tool** | Modern `ironkey` command with subcommands |
| 📦 **Applet Launcher** | Extract & run `.ikp` packages via Wine |
| 🖥️ **GTK4 GUI** | Modern control panel (optional, libadwaita) |

## Quick Start

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt-get install sg3-utils python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 wine32:i386 wine64

# Arch Linux
sudo pacman -S sg3-utils python-gobject gtk4 libadwaita wine
```

### Installation
```bash
git clone https://github.com/yourusername/openironkey
cd openironkey
pip install -e .[gui]    # Full install with GUI
# or
pip install -e .         # Minimal (CLI + PKCS#11 + SCSI)
```

### udev Rules (non-root access)
```bash
sudo tee /etc/udev/rules.d/99-ironkey.rules <<'EOF'
SUBSYSTEM=="scsi_generic", ATTRS{idVendor}=="1953", ATTRS{idProduct}=="0202", MODE="0666", GROUP="plugdev"
EOF
sudo udevadm control --reload && sudo udevadm trigger
# Add yourself to plugdev group: sudo usermod -aG plugdev $USER
```

## Usage

### CLI (`ironkey`)
```bash
ironkey --unlock              # Unlock (prompts for PIN)
ironkey --unlock --pin "xyz"  # Unlock with PIN (not recommended)
ironkey --status              # Device info
ironkey --lock                # Lock device
ironkey --change-pin          # Change PIN
ironkey --list-applets        # List available applets
ironkey --launch-applet CryptoCard  # Launch applet via Wine
```

### Python API
```python
from openironkey.scsi import IronKeySCSI, find_ironkey_device

device = find_ironkey_device()  # e.g. "/dev/sg3"
with IronKeySCSI(device) as dev:
    info = dev.inquiry()
    print(f"Found: {info[8:16].decode().strip()}")
    success = dev.unlock("your-pin")
```

### PKCS#11 (Cryptoki)
```python
from openironkey.pkcs11 import IronKeyPKCS11, CKR_OK

pkcs11 = IronKeyPKCS11()
rv = pkcs11.C_Initialize()
if rv == CKR_OK:
    slots = [0] * 10
    pkcs11.C_GetSlotList(True, slots)
    session = [0]
    pkcs11.C_OpenSession(slots[0], 0, None, None, session)
    pkcs11.C_Login(session[0], 1, b"your-pin", 8)
    # ... crypto operations ...
    pkcs11.C_Logout(session[0])
    pkcs11.C_CloseSession(session[0])
pkcs11.C_Finalize()
```

### Applets
```bash
ironkey-applet --list
ironkey-applet --extract CryptoCard
ironkey-applet --launch CryptoCard -- --help
```

| Applet | Size | Description |
|--------|------|-------------|
| `CryptoCard` | 3.9 MB | Core token management (`token.exe`) |
| `IKOtpApp` | 8.3 MB | RSA SecurID software tokens |
| `IKMalwareScanner` | 8.4 MB | McAfee command-line scanner |
| `IKSecureBackUp` | 2.7 MB | Encrypted network backup |
| `MozillaFirefox` | 29 MB | Portable Firefox + TorButton |
| `SecureSessions` | 8.5 MB | Privoxy/Vidalia/Tor proxy bundle |

### GUI
```bash
ironkey-gui
```
Requires `python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IronKey S200 Device                      │
│  USB Mass Storage (Bulk-Only) + Vendor SCSI Commands       │
└──────────────────────────┬──────────────────────────────────┘
                           │
         ┌─────────────────┼─────────────────┐
         ▼                 ▼                 ▼
┌─────────────────┐ ┌───────────────┐ ┌───────────────┐
│  SCSI Driver    │ │  PKCS#11      │ │  Applet Mgr   │
│  (ironkey_scsi) │ │  (pkcs11)     │ │  (applet)     │
└────────┬────────┘ └───────┬───────┘ └───────┬───────┘
         │                 │                 │
         └─────────────────┼─────────────────┘
                           ▼
              ┌────────────────────────┐
              │      CLI / GUI         │
              └────────────────────────┘
```

## Device Protocol

The IronKey S200 uses **vendor-specific 16-byte SCSI CDBs** (opcode `0x20`):

```
Byte 0: 0x20 (Vendor Specific)
Byte 1: Sub-command (0x03=Auth, 0x00=Data, 0x08=Large Read)
Byte 2: Command ID
Byte 3: Flags
Bytes 4-15: 12-byte session nonce (dynamic, updated per command)
```

### Unlock Sequence (13 commands)
1. `INQUIRY` — Find device
2. `GET_CHALLENGE` (0x20 03 2C 00) → 14-byte challenge
3. `GET_CHALLENGE_RESP` (0x20 03 2C 01) → 2-byte response  
4. `INIT_PIN` (0x20 03 20 00 02) → 2-byte status
5. `NO_OP` (0x20 03 20 03) — Sync
6. `READ_KEY_SLOT_1` (0x20 00 F8 90...) → 31 bytes
7. `READ_KEY_SLOT_2` (0x20 00 06 91...) → 4 bytes
8. `READ_KEY_SLOT_3` (0x20 00 54 CE...) → 128 bytes
9. `READ_DEVICE_INFO` (0x20 08 8A A4...) → 1024 bytes
10. `FINALIZE_INIT` (0x20 03 2C 0A) → 2 bytes
11. `DECRYPT_MASTER_KEY` (0x20 00 D1 35...) → 270 bytes
12. `GET_STATUS` (0x20 00 FF 83...) → 8 bytes
13. `WRITE_UNLOCK` (0x20 00 A9 27...) ← 256-byte unlock token

The **unlock token** is derived from PIN + challenge + key slots via PBKDF2-SHA256 (iterations unknown).

📖 Full protocol docs: [`docs/scsi_protocol.md`](docs/scsi_protocol.md)

## Project Structure
```
openironkey/
├── src/openironkey/
│   ├── scsi/          # SCSI driver (ironkey_scsi.py)
│   ├── pkcs11/        # PKCS#11 module (ironkey_pkcs11.py)
│   ├── cli/           # CLI (ironkey_cli.py)
│   ├── applet/        # Applet launcher (ironkey_applet.py)
│   └── gui/           # GTK4 GUI (ironkey_gui.py)
├── docs/
│   └── scsi_protocol.md
├── tests/
├── setup.py
├── README.md
└── LICENSE
```

## Development
```bash
# Install dev dependencies
pip install -e .[dev]

# Run tests
pytest tests/

# Format code
black src/
mypy src/
```

## Known Limitations

| Area | Status | Notes |
|------|--------|-------|
| **Nonce Derivation** | 🔴 Placeholder | 12-byte session nonce for commands 6-13 needs Windows binary RE |
| **Unlock Token Derivation** | 🔴 Placeholder | PBKDF2-SHA256 params unknown (iterations, salt construction) |
| **PKCS#11 Crypto Ops** | 🟡 Stubs | Encrypt/sign/decrypt need SCSI `CRYPTO_OPERATION` impl |
| **32-bit Applets** | 🟢 Works | Requires `wine32:i386` + `wine64` |
| **Other IronKey Models** | ⚪ Untested | D250, D300, Personal, Enterprise |

## Contributing

We welcome contributions! Priority areas:

1. **Reverse-engineer nonce derivation** — Analyze `ikpkcs11.dll` / `IronKey.exe` in Ghidra/IDA
2. **Implement unlock token derivation** — Determine PBKDF2 parameters
3. **Complete PKCS#11 crypto operations** — Map to SCSI commands
4. **Add support for other IronKey models** — D250, D300, Personal, Enterprise
5. **Improve GTK4 GUI** — Device monitoring, applet management, settings

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for guidelines.

## License

MIT License — see [`LICENSE`](LICENSE) for details.

## References

- **Original binaries**: IronKey Linux (32-bit ELF), Windows `.exe`/`.dll`, `.ikp` applets
- **PKCS#11 v2.40 spec**: https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/
- **Linux SCSI Generic (sg) driver**: https://www.kernel.org/doc/html/latest/driver-api/sg.html
- **sg3-utils**: http://sg.danny.cz/sg/sg3_utils.html

## Acknowledgments

- **IronKey Inc.** — Original hardware & software (discontinued)
- **sg3-utils project** — Linux SCSI tools
- **Python community** — cryptography, pygobject, click, rich

---

*This project is not affiliated with IronKey Inc. or Kingston Technology. It is a community reverse-engineering effort for interoperability and preservation.*