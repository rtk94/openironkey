#!/usr/bin/env python3
"""
IronKey S200 PBKDF2 parameter brute-forcer.

Tries common PBKDF2 parameter combinations against a captured challenge-response pair.

Usage:
    python3 pbkdf2_search.py --challenge <hex> --response <hex> --pin <pin>

Or with a pcap file:
    python3 pbkdf2_search.py --pcap ironkey_unlock.pcapng
"""
import hashlib
import hmac
import struct
import argparse
import sys

# Common PBKDF2 iteration counts observed in IronKey.exe
ITERATION_COUNTS = [
    1000,       # 0x3E8 - most common in binary
    4096,       # 0x1000 - second most common
    10000,      # 0x2710
    50000,
    100000,
    200000,
    600000,     # OWASP recommendation
]

# Common PRF choices
PRFS = [
    ('sha256', hashlib.sha256),
    ('sha1', hashlib.sha1),
    ('sha512', hashlib.sha512),
]

def pbkdf2(password, salt, iterations, dklen, prf_name='sha256'):
    """PBKDF2 with configurable PRF."""
    if prf_name == 'sha256':
        return hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)
    elif prf_name == 'sha1':
        return hashlib.pbkdf2_hmac('sha1', password, salt, iterations, dklen)
    elif prf_name == 'sha512':
        return hashlib.pbkdf2_hmac('sha512', password, salt, iterations, dklen)
    else:
        raise ValueError(f"Unknown PRF: {prf_name}")

def try_combinations(pin, challenge, expected_response):
    """Try all PBKDF2 parameter combinations."""
    print(f"Testing PBKDF2 with:")
    print(f"  PIN: {pin}")
    print(f"  Challenge: {challenge.hex()}")
    print(f"  Expected: {expected_response.hex()}")
    print()
    
    pin_bytes = pin.encode('utf-8')
    
    # Common salts and data constructions
    salt_options = [
        ("challenge as salt", challenge),
        ("challenge + pin as salt", challenge + pin_bytes),
        ("pin as salt", pin_bytes),
        ("empty salt", b''),
    ]
    
    password_options = [
        ("pin", pin_bytes),
        ("challenge + pin", challenge + pin_bytes),
        ("pin + challenge", pin_bytes + challenge),
    ]
    
    dklen_options = [32, 16, 20, 64]  # SHA256, MD5, SHA1, SHA512 output sizes
    
    total = len(ITERATION_COUNTS) * len(PRFS) * len(salt_options) * len(password_options) * len(dklen_options)
    print(f"Total combinations: {total:,}")
    print()
    
    count = 0
    for iterations in ITERATION_COUNTS:
        for prf_name, prf_func in PRFS:
            for salt_name, salt in salt_options:
                for pwd_name, pwd in password_options:
                    for dklen in dklen_options:
                        count += 1
                        if count % 1000 == 0:
                            print(f"\r  Tested {count:,}/{total:,}...", end='', flush=True)
                        
                        try:
                            derived = pbkdf2(pwd, salt, iterations, dklen, prf_name)
                            if derived[:len(expected_response)] == expected_response:
                                print()
                                print(f"\n✅ FOUND MATCH!")
                                print(f"  Iterations: {iterations}")
                                print(f"  PRF: {prf_name}")
                                print(f"  Salt: {salt_name} ({salt.hex()})")
                                print(f"  Password: {pwd_name} ({pwd.hex()})")
                                print(f"  DK length: {dklen}")
                                print(f"  Derived: {derived.hex()}")
                                return True
                        except Exception:
                            continue
    
    print()
    print(f"❌ No match found after {count:,} combinations")
    return False

def main():
    parser = argparse.ArgumentParser(description='IronKey PBKDF2 parameter search')
    parser.add_argument('--pin', help='PIN to test (e.g., "1234")')
    parser.add_argument('--challenge', help='Challenge hex string')
    parser.add_argument('--response', help='Expected response hex string')
    parser.add_argument('--pcap', help='Parse challenge/response from pcap file')
    
    args = parser.parse_args()
    
    if args.pcap:
        print("PCAP parsing not yet implemented.")
        print("Use --challenge and --response manually for now.")
        print()
        print("To get challenge/response from USBPcap:")
        print("  1. Capture unlock with capture_usbpcap.py instructions")
        print("  2. Parse with: python3 parse_usbpcap.py ironkey_unlock.pcapng")
        print("  3. Extract challenge (from GET_CHALLENGE data phase)")
        print("  4. Extract response (from VERIFY_CHALLENGE data phase)")
        sys.exit(1)
    
    if not args.pin or not args.challenge or not args.response:
        print("Error: --pin, --challenge, and --response required")
        print()
        print("Example:")
        print("  python3 pbkdf2_search.py --pin 1234 \\")
        print("    --challenge 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \\")
        print("    --response deadbeef...")
        sys.exit(1)
    
    pin = args.pin
    challenge = bytes.fromhex(args.challenge)
    response = bytes.fromhex(args.response)
    
    try_combinations(pin, challenge, response)

if __name__ == "__main__":
    main()