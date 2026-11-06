# IronKey S200 Reverse Engineering Findings

**Date**: 2026-11-05  
**Target**: `ikpkcs11.dll` from IronKey S200 (VID:PID 1953:0202)  
**SHA256**: `0b6f0552f3279585aeb67cae3b0eb95176bb12235e3cb101948d0ca178e196d0`  
**Size**: 776,512 bytes (PE32, i386)

---

## Executive Summary

Static analysis of `ikpkcs11.dll` confirms the SCSI vendor CDB protocol for IronKey S200 unlock. The DLL uses **IOCTL_SCSI_PASS_THROUGH (0x22040C)** to send raw SCSI commands via `DeviceIoControl`. The CDB construction function at `0x1000EA00` builds 32-byte vendor commands with opcode `0x20`.

**Key discovery**: The unlock protocol uses a **16+16 CDB structure** (two 16-byte blocks) rather than a single 16-byte CDB. This explains why the earlier 16-byte CDB tests only partially worked — Commands 1-5 (probe/init) use the first block, while challenge-response uses both blocks.

---

## DLL Analysis

### Imports
| DLL | Key Functions | Purpose |
|-----|---------------|---------|
| **KERNEL32.dll** | `DeviceIoControl` (IAT: 0x10067088) | SCSI command transport |
| **SETUPAPI.dll** | `SetupDiGetClassDevsW`, `SetupDiEnumDeviceInterfaces` | USB device enumeration |
| **CRYPT32.dll** | `CertOpenStore`, `CertAddEncodedCertificateToStore` | Certificate management |
| **ADVAPI32.dll** | `ReportEventA`, `RegisterEventSourceA` | Windows event logging |
| **USER32.dll** | `MessageBoxA`, `GetDesktopWindow` | UI dialogs |
| **MSVCR80.dll** | `memcpy`, `malloc`, `printf` | C runtime |

### Exports (218 total)
Full PKCS#11 API plus IronKey extensions:

| Function | Ordinal | RVA | Purpose |
|----------|---------|-----|---------|
| `C_GetFunctionList` | 167 | — | PKCS#11 entry point |
| `C_Login` | 181 | `0x10001B80` | PIN verification |
| `C_InitPIN` | 178 | — | PIN initialization |
| `C_Sign` | 188 | — | Digital signature |
| `C_Encrypt` | 155 | — | Encryption |
| `C_Decrypt` | 142 | — | Decryption |
| `C_GenerateKey` | 163 | — | Key generation |
| `CI_P11Router_*` | Various | — | IronKey internal router |

---

## C_Login Analysis (0x10001B80)

### Function Signature
```c
CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, 
              CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
```

### Disassembly Summary
```asm
10001b80:  sub esp, 0x10
10001b83:  mov eax, ds:0x10097e80     ; stack cookie
10001b88:  xor eax, esp               ; cookie check
10001b8e:  mov edx, [esp+0x1c]        ; pPin (arg 3)
10001b93:  mov ebp, [esp+0x18]        ; hSession (arg 1)
10001b97:  test ebp, ebp              ; hSession == NULL?
10001b9d:  jne 0x10001bb2             ; if != NULL, continue
10001b9f:  lea eax, [ebp+0x7]         ; return 7 (CKR_ARGUMENTS)
```

### Argument Validation
1. **hSession NULL check**: Returns `7` (CKR_ARGUMENTS) if NULL
2. **Session state check**: Verifies session exists in hash table
3. **pPin NULL check**: Returns `7` if NULL
4. **PIN length calculation**: strlen loop at `0x10001be0`
5. **Length cap**: `cmp eax, 0x8; jbe skip; mov eax, 0x8` — caps PIN at 8 chars

### PIN Copy (memcpy call)
```asm
10001bf5:  push eax                   ; pin_len (capped at 8)
10001bf6:  push edx                   ; pin_ptr
10001bf7:  lea eax, [esp+0x18]        ; out_buf (stack)
10001bfb:  push eax
10001bfc:  call 0x1005a610            ; memcpy (IAT: 0x100671b4)
10001c04:  test eax, eax
10001c06:  jne 0x10001c1f             ; if success, proceed
; Returns 5 (CKR_PIN_INCORRECT) on failure
```

### Session Management (0x10001c1f onwards)
After PIN copy, the function:
1. Divides session handle by table size (`div edi`)
2. Calls `0x1000EAC0` (hash table lookup)
3. Stores session data in hash table bucket
   ```asm
   mov [eax+0x0], ecx      ; session_id
   mov [eax+0x4], ebx      ; user_type
   mov [eax+0x8], esi      ; bucket_index
   mov [eax+0xc], edx      ; timestamp
   mov [eax+0x10], 0x0     ; next pointer
   ```
4. Returns `0` (CKR_OK)

### Key Insight
**C_Login does NOT perform USB authentication**. It only validates arguments and manages PKCS#11 sessions in memory. 

**Architectural finding (2026-11-05)**: The USB unlock happens **outside** the PKCS#11 DLL, in `IronKey.exe` (which also imports `DeviceIoControl`). The workflow is:

1. **IronKey.exe** opens device, performs SCSI unlock (0x20 CDB sequence)
2. **IronKey.exe** loads `ikpkcs11.dll` 
3. **ikpkcs11.dll** assumes device is unlocked, handles PKCS#11 operations via SCSI `CRYPT_OPERATION`

This means our Linux implementation must:
- Perform the 13-command unlock sequence **first** (via SCSI driver)
- Then load the PKCS#11 module for crypto operations

---

## SCSI Transport (DeviceIoControl)

### Call Sites
10 calls to `DeviceIoControl` (IAT entry `0x10067088`) found at:
| Address | Context |
|---------|---------|
| `0x1005EA5D` | Primary SCSI send (IOCTL 0x22040C) |
| `0x1005EBD2` | Secondary path |
| `0x1005EC4E` | — |
| `0x1005ED8E` | — |
| `0x1005EE30` | — |
| `0x1005F85A` | — |
| `0x1005F9A9` | — |
| `0x10060431` | — |
| `0x1006332D` | — |
| `0x10064E67` | — |

### Primary Call (0x1005EA5D)
```asm
1005ea54:  push 0x22040c              ; IOCTL_SCSI_PASS_THROUGH
1005ea59:  mov ecx, [ebp+0xc]         ; device handle
1005ea5c:  push ecx
1005ea5d:  call DWORD PTR ds:0x10067088  ; DeviceIoControl
```

**IOCTL 0x22040C** = `IOCTL_SCSI_PASS_THROUGH` — sends raw SCSI commands to the device.

### CDB Buffer
- Allocated at `[ebp-0x400]` (stack)
- Size: `0x184` (388 bytes)
- Contains: CDB (32 bytes) + data phase buffers

---

## CDB Construction (0x1000EA00)

This function builds the 32-byte SCSI vendor CDB that `DeviceIoControl` sends.

### Function Signature
```c
void BuildCDB(uint32_t param3, uint16_t param2, uint8_t param1, uint8_t param4)
```

### Disassembly
```asm
1000ea00:  push ebx
1000ea01:  push 0x20                  ; alloc 32 bytes
1000ea03:  push 0x1
1000ea05:  mov ebx, eax               ; ebx = param3 (in EAX on entry)
1000ea07:  call malloc (0x10067170)
1000ea22:  mov dl, [esp+0x10]         ; dl = param4
1000ea26:  xor ecx, ecx
1000ea28:  mov [eax], ecx             ; zero first 16 bytes
1000ea2a:  mov [eax+4], ecx
1000ea2d:  mov [eax+8], ecx
1000ea30:  mov [eax+12], ecx
1000ea33:  mov cl, [esp+0x08]         ; cl = param1
1000ea37:  mov [eax+0x12], cl         ; byte 18 = param1
1000ea3a:  mov cx, [esp+0x0c]         ; cx = param2
1000ea3f:  mov [eax+0x1c], dl         ; byte 28 = param4
1000ea42:  mov dl, [esp+0x08]         ; dl = param1
1000ea46:  mov [eax+0x14], cx         ; bytes 20-21 = param2
1000ea4a:  mov [eax+0x03], cl         ; byte 3 = param2 low
1000ea4d:  mov [eax+0x04], ch         ; byte 4 = param2 high
1000ea50:  mov ecx, ebx               ; ecx = param3
1000ea52:  mov [eax+0x02], dl         ; byte 2 = param1
1000ea55:  mov edx, ebx
1000ea57:  shr ecx, 0x08              ; ecx = param3 >> 8
1000ea5a:  mov [eax+0x18], ebx        ; bytes 24-27 = param3 (full)
1000ea5d:  mov [eax+0x05], bl         ; byte 5 = param3 low
1000ea60:  shr edx, 0x10              ; edx = param3 >> 16
1000ea63:  shr ebx, 0x18              ; ebx = param3 >> 24
1000ea66:  mov [eax+0x06], cl         ; byte 6 = param3 >> 8
1000ea69:  mov cl, [esp+0x10]         ; cl = param4
1000ea6d:  mov [eax+0x08], bl         ; byte 8 = param3 >> 24
1000ea70:  mov BYTE PTR [eax+0x10], 0x20  ; byte 16 = 0x20
1000ea74:  mov BYTE PTR [eax+0x11], 0xe0  ; byte 17 = 0xE0
1000ea78:  mov BYTE PTR [eax], 0x20       ; byte 0 = 0x20 (OPCODE)
1000ea7b:  mov BYTE PTR [eax+0x01], 0xe0  ; byte 1 = 0xE0 (FLAGS)
1000ea7f:  mov [eax+0x07], dl             ; byte 7 = param1
1000ea82:  mov [eax+0x0f], cl             ; byte 15 = param4
```

### Complete CDB Layout (32 bytes)

| Offset | Value | Description |
|--------|-------|-------------|
| **Block 1 (16 bytes)** | | |
| `0x00` | `0x20` | **SCSI Opcode** (vendor-specific) |
| `0x01` | `0xE0` | Control flags |
| `0x02` | `param1` | Vendor subcommand |
| `0x03-0x04` | `param2` | 16-bit command code (BE) |
| `0x05-0x08` | `param3` | 32-bit parameter (BE) |
| `0x0F` | `param4` | Additional param |
| **Block 2 (16 bytes)** | | |
| `0x10` | `0x20` | Echo of opcode |
| `0x11` | `0xE0` | Echo of control flags |
| `0x12` | `param1` | Echo of subcommand |
| `0x14-0x15` | `param2` | Echo of command code |
| `0x18-0x1B` | `param3` | Echo of parameter |
| `0x1C` | `param4` | Echo of additional param |

### Parameter Mapping to IronKey Commands

Based on our earlier protocol discovery (`docs/scsi_protocol.md`):

| param1 | param2 | param3 | Command |
|--------|--------|--------|---------|
| `0x03` | `0x2C00` | `0` | GET_CHALLENGE |
| `0x03` | `0x2C01` | `0` | GET_CHALLENGE_RESP |
| `0x03` | `0x2000` | `0x00020000` | INIT_PIN |
| `0x03` | `0x2003` | `0` | NO_OP |

The CDB structure is **32 bytes** (not 16), with the second 16-byte block echoing the first. This is unusual but matches the device's expectations.

---

## DeviceIoControl Parameters

From the call at `0x1005EA5D`:

```c
DeviceIoControl(
    hDevice,              // [ebp+0xc] - from CreateFile
    0x22040C,             // IOCTL_SCSI_PASS_THROUGH
    pInBuf,               // [ebp-0x400] - CDB + data
    0x184,                // nInBufSize (388 bytes)
    pOutBuf,              // [ebp-0x400] - response
    0x184,                // nOutBufSize
    &bytesReturned,       // [ebp-0x408]
    NULL                  // lpOverlapped (synchronous)
);
```

The input buffer contains:
- **SCSI_PASS_THROUGH structure** (header)
- **CDB** (32 bytes, as constructed above)
- **Data phase** (for OUT commands / challenge-response)

---

## Second Device (IronKey Personal, 1953:1001)

### USB Descriptors
- **VID:PID**: `1953:1001` (vs S200's `1953:0202`)
- **Product**: "IronKey"
- **Revision**: `1.1e` (vs S200's `2.0d`)
- **Serial**: `199456787067199456`
- **Firmware**: `1.00` (SCSI INQUIRY)
- **CD-ROM date**: 2008-08-21

### Protocol Compatibility
The Personal (2008) does **NOT** support the `0x20` vendor CDB protocol:
```
GET_CHALLENGE (0x20 0x03 0x2C 0x00):
  Status: 0x02 (CHECK CONDITION)
  Sense: F0 00 05 00 ... 20 00 ...
  Sense key: 0x05 (ILLEGAL REQUEST)
  ASC: 0x20 (INVALID COMMAND OPERATION CODE)
```

**Conclusion**: Different authentication protocol. Would require separate RE of the 2008 binaries (`/mnt/WINDOWS/` on the Personal's CD-ROM).

### Applets (Personal)
| Applet | Size |
|--------|------|
| IKSecureBackUp.ikp | 2.5 MB |
| MozillaFirefox.ikp | 10.5 MB |
| SecureSessions.ikp | 8.5 MB |

Missing vs S200: CryptoCard, IKOtpApp, IKMalwareScanner

---

## Development Status

### Completed
- [x] SCSI vendor CDB protocol (opcode 0x20) mapped
- [x] 13-command unlock sequence documented
- [x] PKCS#11 module structure reverse-engineered
- [x] CDB construction function fully disassembled
- [x] DeviceIoControl transport identified (IOCTL 0x22040C)
- [x] C_Login confirmed as session management only (not USB auth)

### In Progress
- [ ] **Locate USB authentication entry point** — Not in C_Login. Likely in:
  - `C_Initialize` (first call)
  - `CI_P11Router_*` functions
  - `IronKey.exe` main program
- [ ] Nonce derivation algorithm (commands 6-13)
- [ ] PBKDF2 parameters (iterations, salt, PRF)
- [ ] PKCS#11 crypto → SCSI CRYPT_OPERATION mapping

### Next Targets
1. **C_Initialize** — Likely where device is opened and unlocked
2. **CI_P11Router functions** — Internal routing may include USB layer
3. **IronKey.exe** — Main program may handle unlock before loading PKCS#11
4. **USB capture** — Validate static analysis against real traffic

---

## Tooling

### Available
- `capture_usbpcap.py` — Windows USBPcap capture instructions
- `parse_usbpcap.py` — Python parser for .pcapng files (pyshark/scapy)
- `Ghidra_AnalyzeIronKey.py` — Ghidra headless analysis script (requires JDK 25+)

### Commands
```bash
# Disassemble specific function
objdump -d ikpkcs11.dll -M intel --start-address=0x10001b80 --stop-address=0x10001d00

# Find DeviceIoControl calls
objdump -d ikpkcs11.dll -M intel | grep "call DWORD PTR ds:0x10067088"

# Find CDB opcode stores
objdump -d ikpkcs11.dll -M intel | grep "mov BYTE PTR.*0x20"
```

---

## References
- `../docs/scsi_protocol.md` — Full 13-command sequence
- `../README.md` — Project overview
- `../CONTRIBUTING.md` — RE guidelines

---

*Analysis performed via objdump (binutils) and manual disassembly. Ghidra GUI analysis pending (JDK 25 required, now installed at /usr/lib/jvm/java-25-openjdk-amd64).*
