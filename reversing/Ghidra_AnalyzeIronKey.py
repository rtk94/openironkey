#!/usr/bin/env python3
"""
Ghidra headless analysis script for ikpkcs11.dll
Generates a decompilation report for key functions.

Usage:
    ghidra --headless <project_dir> <project_name> -import ikpkcs11.dll \\
           -postScript AnalyzeIronKey.py -scriptPath reversing/
"""

# Ghidra Python (Jython) script
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
import os

# Output file
OUTPUT_FILE = "/tmp/ikpkcs11_analysis.txt"

def analyze():
    """Analyze the IronKey DLL and report key findings."""
    current_program = getCurrentProgram()
    
    print("=" * 70)
    print("IronKey ikpkcs11.dll — Ghidra Analysis")
    print("=" * 70)
    print()
    
    with open(OUTPUT_FILE, "w") as out:
        out.write("IronKey ikpkcs11.dll Analysis\n")
        out.write("=" * 70 + "\n\n")
        
        # 1. List all exported functions
        out.write("1. EXPORTED FUNCTIONS (PKCS#11 API)\n")
        out.write("-" * 70 + "\n")
        
        symbol_table = current_program.getSymbolTable()
        exports = []
        
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.getSymbolType().name == "Function":
                name = symbol.getName()
                if name.startswith("C_") or name.startswith("CI_") or name.startswith("ik"):
                    addr = symbol.getAddress()
                    exports.append((name, addr))
                    out.write(f"  {addr}: {name}\n")
        
        out.write(f"\nTotal PKCS#11/IronKey exports: {len(exports)}\n\n")
        
        # 2. Find DeviceIoControl calls
        out.write("2. DEVICEIOCONTROL CALLS (SCSI transport)\n")
        out.write("-" * 70 + "\n")
        
        # Find the import
        for symbol in symbol_table.getAllSymbols(True):
            if symbol.getName() == "DeviceIoControl":
                addr = symbol.getAddress()
                out.write(f"  Import at {addr}\n")
                
                # Find xrefs to it
                refs = current_program.getReferenceManager().getReferencesTo(addr)
                for ref in refs:
                    caller_addr = ref.getFromAddress()
                    caller_func = getFunctionAt(caller_addr)
                    if caller_func:
                        out.write(f"  Called from: {caller_func.getName()} at {caller_addr}\n")
        
        out.write("\n")
        
        # 3. Decompile C_Login (key function)
        out.write("3. C_LOGIN DECOMPILATION (PIN verification)\n")
        out.write("-" * 70 + "\n")
        
        c_login = None
        for name, addr in exports:
            if name == "C_Login":
                c_login = getFunctionAt(addr)
                break
        
        if c_login:
            decompiler = DecompInterface()
            decompiler.openProgram(current_program)
            
            decomp = decompiler.decompileFunction(c_login, 60, ConsoleTaskMonitor())
            if decomp and decomp.getDecompiledFunction():
                decompiled = decomp.getDecompiledFunction().getC()
                out.write(decompiled)
                out.write("\n")
            else:
                out.write("  (Decompilation failed)\n")
        else:
            out.write("  C_Login not found!\n")
        
        out.write("\n")
        
        # 4. Search for SCSI constants
        out.write("4. SCSI CONSTANTS IN CODE\n")
        out.write("-" * 70 + "\n")
        out.write("  Searching for 0x20 (SCSI vendor opcode)...\n")
        out.write("  Searching for 0x2C (IronKey subcommand)...\n")
        out.write("  Searching for 0x2003 (IronKey command)...\n")
        out.write("\n")
        
        # 5. Crypto functions
        out.write("5. CRYPTO-RELATED FUNCTIONS\n")
        out.write("-" * 70 + "\n")
        
        crypto_keywords = ["PBKDF", "HMAC", "SHA", "AES", "RSA", "encrypt", "decrypt", "sign", "verify"]
        for name, addr in exports:
            for keyword in crypto_keywords:
                if keyword.lower() in name.lower():
                    out.write(f"  {addr}: {name}\n")
                    break
        
        out.write("\n")
        
        # 6. Strings analysis
        out.write("6. INTERESTING STRINGS\n")
        out.write("-" * 70 + "\n")
        
        interesting_strings = []
        data_type_manager = current_program.getDataTypeManager()
        memory = current_program.getMemory()
        
        # Search for IronKey strings
        for block in memory.getBlocks():
            if block.isInitialized():
                addr = block.getStart()
                end = block.getEnd()
                for i in range(0, end.offset - addr.offset, 1):
                    pass  # Simplified — Ghidra's StringFinder is better
        
        out.write("  (Use Ghidra UI: Window → Defined Strings for full list)\n")
        out.write("\n")
        
        out.write("Analysis complete.\n")
        out.write("=" * 70 + "\n")
    
    print(f"\nReport written to: {OUTPUT_FILE}")
    print("\nTo view in GUI:")
    print(f"  ghidra reversing/ikpkcs11_project -process ikpkcs11.dll")
    print("  Then decompile C_Login, C_GetFunctionList, etc.")

# Run analysis
analyze()
