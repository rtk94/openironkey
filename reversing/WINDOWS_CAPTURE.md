# Windows USB Capture Checklist
## For IronKey S200 (1953:0202) Unlock Analysis

**Goal**: Capture the SCSI challenge-response sequence to reverse-engineer nonce derivation and PBKDF2 parameters.

**Estimated time**: 30-60 minutes (including VM setup if needed)

---

## Option A: Windows VM (Recommended)

### Prerequisites
- [ ] QEMU/KVM installed (confirmed: ✓)
- [ ] Windows ISO (Windows 10/11 trial or existing license)
- [ ] 4GB+ RAM free
- [ ] IronKey S200 plugged in

### Steps

#### 1. Create VM
```bash
# Create VM with USB passthrough
virt-manager --connect qemu:///system \
  --name IronKey-RE \
  --memory 4096 \
  --vcpus 2 \
  --disk path=/tmp/win11.qcow2,size=40,format=qcow2 \
  --cdrom /path/to/windows11.iso \
  --os-variant win11 \
  --network network=default \
  --graphics spice,listen=127.0.0.1
```

#### 2. Install Windows
- [ ] Install Windows 11 (or 10)
- [ ] Install virtio drivers (from Fedora virtio-win ISO)
- [ ] Install Spice guest tools

#### 3. Configure USB Passthrough
```bash
# Find IronKey USB device
lsusb | grep 1953
# Output: Bus 003 Device 008: ID 1953:0202 Ironkey Inc. S200 2GB Rev. 1

# Add to VM (virt-manager GUI or XML):
# <hostdev mode='subsystem' type='usb'>
#   <source>
#     <vendor id='0x1953'/>
#     <product id='0x0202'/>
#   </source>
# </hostdev>
```

**Alternative**: In virt-manager GUI:
- VM → Details → Add Hardware → USB Host Device → Select IronKey (1953:0202)

#### 4. Install USBPcap in VM
```powershell
# Download: https://desowin.org/usbpcap/
# Install with default options
# Reboot VM
```

#### 5. Install Wireshark in VM
```powershell
# Download: https://www.wireshark.org/download.html
# Install with USBPcap support (checked by default)
```

#### 6. Copy IronKey Files to VM
- [ ] Copy `C:\IronKey\` from the CD-ROM (or insert CD-ROM into VM)
- [ ] Or: Share folder from host

#### 7. Perform Capture
```powershell
# Terminal 1 (Administrator):
tshark -D  # Note the interface number for IronKey

# Start capture:
usbpcapcmd -d \\.\USBPcap1 -o C:\ironkey_unlock.pcapng
# (Adjust USBPcap1 to match tshark output)

# Terminal 2:
cd C:\IronKey\WINDOWS
.\IronKey.exe
# Enter PIN in GUI
# Wait for unlock completion

# Terminal 1: Ctrl+C to stop capture
```

#### 8. Extract Capture
- [ ] Copy `ironkey_unlock.pcapng` to host (shared folder, USB, network)
- [ ] On host: `python3 parse_usbpcap.py ironkey_unlock.pcapng`

---

## Option B: Static Analysis Only (No Windows)

If VM setup is too much, continue with Ghidra analysis:

### Ghidra Setup
```bash
# JDK 25 is installed at /usr/lib/jvm/java-25-openjdk-amd64
export JAVA_HOME=/usr/lib/jvm/java-25-openjdk-amd64

# Open IronKey.exe in Ghidra
ghidra --headless -import IronKey.exe -postScript AnalyzeIronKey.py
```

### Key Functions to Find
1. **Search for**: `0x22040c` (IOCTL_SCSI_PASS_THROUGH)
2. **Find callers**: Functions that push this value
3. **Decompile**: Look for:
   - XOR loops (HMAC, PBKDF2)
   - SHA256 constants (0x428a2f98, 0x71374491, etc.)
   - Loops with 1000/4096 iterations
   - Memory copies of 32 bytes (challenge/response)

### What We're Looking For
```
PIN (user input)
  ↓
PBKDF2(PIN, salt, iterations=1000/4096, PRF=HMAC-SHA256)
  ↓
Derived key (32 bytes)
  ↓
HMAC-SHA256(derived_key, challenge)
  ↓
Response (sent via SCSI 0x20 CDB)
```

---

## Option C: Wine + Wireshark (Partial)

⚠️ **Limitation**: Wine cannot load USBPcap (kernel driver). USB traffic cannot be captured this way.

**What Wine CAN do:**
- Run `IronKey.exe` (may work for GUI)
- Analyze the PE file with tools like `winedump`, `objdump`

**What Wine CANNOT do:**
- Capture USB traffic (no USBPcap)
- Access IronKey hardware (Wine USB support is limited)

**Verdict**: Wine is not suitable for this task.

---

## Option D: ReactOS (Not Recommended)

ReactOS is open-source Windows, but:
- Incomplete Win32 API
- IronKey.exe may not run
- USB stack may not support the device
- Not worth the risk

---

## Capture Quality Checklist

### Before Capture
- [ ] IronKey S200 inserted (not the Personal 1953:1001)
- [ ] Device is LOCKED (re-insert if needed)
- [ ] USBPcap interface selected correctly
- [ ] Capture file path is writable
- [ ] IronKey.exe path is correct

### During Capture
- [ ] Start capture BEFORE launching IronKey.exe
- [ ] Enter PIN correctly
- [ ] Wait for full unlock (both partitions mounted)
- [ ] Stop capture AFTER unlock completes

### After Capture
- [ ] File size > 0 (should be 100KB-10MB)
- [ ] Copy to Linux host
- [ ] Run parser: `python3 parse_usbpcap.py ironkey_unlock.pcapng`
- [ ] Verify challenge-response pairs found

### Expected Capture Contents
| Packet | Description |
|--------|-------------|
| USB Setup | Device enumeration |
| SCSI INQUIRY | Device identification |
| SCSI 0x20 0x03 0x2C 0x00 | GET_CHALLENGE (14 bytes data) |
| SCSI 0x20 0x03 0x2C 0x01 | GET_CHALLENGE_RESP (2 bytes) |
| SCSI 0x20 0x03 0x20 0x00 | INIT_PIN |
| ... | (commands 6-13: nonce derivation) |
| SCSI 0x20 0x03 0x20 0x02 | UNLOCK_ME (token) |
| SCSI 0x20 0x03 0x20 0x03 | NO_OP (verify) |

---

## Troubleshooting

### "No USBPcap interfaces found"
- Reboot VM after USBPcap install
- Check Device Manager → USB controllers → USBPcap
- Run `tshark -D` in Administrator PowerShell

### "Device not found" in IronKey.exe
- Verify USB passthrough: `lsusb` in VM should show 1953:0202
- Check virt-manager: VM → Details → USB Host Device
- Try different USB port in host

### "Access denied" when capturing
- Run PowerShell as Administrator
- Check USBPcap service is running: `sc query USBPcap`

### "Capture file is empty"
- Did IronKey.exe actually unlock?
- Check if device was locked before capture
- Verify INQUIRY packets in Wireshark

---

## Output Analysis

### Parser Output
```
[42] GET_CHALLENGE (0x2C00)
  CDB: 2003e0002c00000000...
  Data: 14 bytes challenge

[58] GET_CHALLENGE_RESP (0x2C01)
  CDB: 2003e0002c01000000...
  Data: 2 bytes response

[156] INIT_PIN (0x2000)
  CDB: 2003e00020000200...
  
[172] NO_OP (0x2003)
  CDB: 2003e00020030000...
```

### PBKDF2 Search
```bash
python3 pbkdf2_search.py \
  --pin 1234 \
  --challenge <14-byte hex from GET_CHALLENGE> \
  --response <2-byte hex from GET_CHALLENGE_RESP>
```

---

## Safety Reminders

⚠️ **Use the S200 (1953:0202)**, not the Personal (1953:1001) — different protocol  
⚠️ **Read-only capture** — USBPcap does not modify traffic  
⚠️ **PIN**: Use a test PIN, not your real one (traffic is visible in capture)  
⚠️ **VM isolation**: Capture VM cannot harm host system  

---

*Checklist created: 2026-11-05*  
*Next: VM setup or Ghidra deep dive on IronKey.exe*
