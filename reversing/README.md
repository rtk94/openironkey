# IronKey S200 Reverse Engineering

## Overview
This directory contains analysis tools and methodology for reverse-engineering the IronKey S200 secure USB drive unlock protocol.

## Current Status

### ✅ Completed
- [x] SCSI vendor CDB protocol (opcode 0x20) fully mapped
- [x] 13-command unlock sequence documented in `docs/scsi_protocol.md`
- [x] PKCS#11 module structure reverse-engineered (`ikpkcs11.dll`)
- [x] CLI, GUI, and applet launcher functional (waiting on unlock)
- [x] GitHub repository published with branch protection

### 🔍 In Progress
- [ ] Nonce derivation (commands 6-13) — need `ikpkcs11.dll` analysis
- [ ] Unlock token derivation (PBKDF2 parameters)
- [ ] PKCS#11 crypto operation mapping to SCSI `CRYPT_OPERATION`

### 📋 Tools Available

#### Static Analysis
| Tool | Purpose | File |
|------|---------|------|
| Ghidra | Decompile `ikpkcs11.dll` | `ikpkcs11.dll` |
| IDA Pro | Alternative to Ghidra | `ikpkcs11.dll` |
| objdump | Export/import table analysis | CLI |

#### Dynamic Analysis (Windows)
| Tool | Purpose | File |
|------|---------|------|
| USBPcap | Capture USB traffic during unlock | `capture_usbpcap.py` |
| Python parser | Extract SCSI commands from .pcapng | `parse_usbpcap.py` |
| Wireshark | Manual analysis of capture | — |

## Ghidra Analysis Guide

### Target Binary
```
ikpkcs11.dll (776,512 bytes)
SHA256: 0b6f0552f3279585aeb67cae3b0eb95176bb12235e3cb101948d0ca178e196d0
```

### Key Exports (218 total)
Full PKCS#11 API plus IronKey extensions:

| Function | Ordinal | Purpose |
|----------|---------|---------|
| `C_GetFunctionList` | 167 | PKCS#11 entry point |
| `C_Login` | 181 | PIN verification → SCSI unlock |
| `C_InitPIN` | 178 | PIN initialization |
| `C_GenerateKey` | 163 | Key generation |
| `C_Sign` | 188 | Digital signature → `CRYPT_OPERATION` |
| `C_Encrypt` | 155 | Encryption → `CRYPT_OPERATION` |
| `C_Decrypt` | 142 | Decryption → `CRYPT_OPERATION` |
| `CI_P11Router_*` | Various | IronKey internal router |

### Key Imports
| DLL | Functions | Purpose |
|-----|-----------|---------|
| `KERNEL32.dll` | `DeviceIoControl` | SCSI command transport |
| `SETUPAPI.dll` | `SetupDiGetClassDevsW` | USB device enumeration |
| `CRYPT32.dll` | `CertOpenStore`, etc. | Certificate store |

### Ghidra Workflow
1. **Import**: File → Import File → `ikpkcs11.dll`
2. **Analyze**: Auto-analysis (recommended settings)
3. **Focus areas**:
   - `C_Login` (ordinal 167) — PIN → unlock sequence
   - `C_GetFunctionList` (ordinal 167) — function table
   - Search for: `DeviceIoControl` (SCSI transport)
   - Search for: `0x20` (SCSI opcode), `0x2C` (IronKey subcommand)
   - Search for: `PBKDF2`, `HMAC`, `SHA256` (crypto)
   - Strings: `IronKey`, `challenge`, `nonce`, `token`

4. **Decompile**: Right-click function → Decompile
5. **Document**: Record findings in `docs/scsi_protocol.md`

### Expected Findings
- **Nonce derivation**: How commands 6-13 derive the nonce from the challenge
- **PBKDF2 parameters**: Iteration count, salt length, PRF (HMAC-SHA256?)
- **Token format**: 32-byte structure sent in `UNLOCK_TOKEN` command
- **Crypto mapping**: PKCS#11 mechanisms → SCSI `CRYPT_OPERATION` subcommands

## USBPcap Capture (Windows)

### Prerequisites
1. Install USBPcap: https://desowin.org/usbpcap/download.html
2. Install Wireshark: https://www.wireshark.org/download.html
3. Run PowerShell as Administrator

### Capture Steps
```powershell
# 1. Insert IronKey S200
# 2. List interfaces
tshark -D

# 3. Start capture (adjust interface number)
usbpcapcmd -d \\.\\USBPcap1 -o ironkey_unlock.pcapng

# 4. Run IronKey.exe and enter PIN (in another terminal)
cd C:\IronKey\WINDOWS
IronKey.exe

# 5. Stop capture (Ctrl+C)
# 6. Copy .pcapng to Linux
```

### Analysis
```bash
# Install parser dependencies
pip install pyshark

# Parse the capture
python3 parse_usbpcap.py ironkey_unlock.pcapng
```

### Wireshark Filters
```
usb.bus_id == 1 && usb.device_address == 5
usb.endpoint_number != 0
scsi.cmd.opcode == 0x20
```

## Documentation

| Document | Contents |
|----------|----------|
| `../docs/scsi_protocol.md` | Full 13-command unlock sequence |
| `../README.md` | Project overview and quick start |
| `../CONTRIBUTING.md` | RE guidelines and priorities |

## Safety Notes

⚠️ **READ-ONLY ANALYSIS**: The commands in this directory are for analysis only.
- The Ghidra analysis does not modify the DLL
- USBPcap captures traffic passively (no injection)
- The Python parser only reads .pcapng files

⚠️ **DEVICE SAFETY**:
- The S200 supports the 0x20 CDB protocol (safe to test)
- The older Personal (1953:1001) does NOT support 0x20 (returns ILLEGAL REQUEST)
- Never send write commands to a device with important data

## Next Steps

1. **Ghidra analysis** of `ikpkcs11.dll` — find `C_Login` and decompile
2. **USB capture** — record real unlock on Windows
3. **Compare** — validate static analysis against dynamic capture
4. **Implement** — complete nonce derivation and PBKDF2 in Python
5. **Test** — unlock sequence on Linux S200

---

*Last updated: 2026-11-05*
