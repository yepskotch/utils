#!/usr/bin/env python3
"""ft - faketime wrapper that auto-calculates clock skew against a target host.

Requirements:
    ntpdate   - clock sync query (apt: ntpdate)
    faketime  - time spoofing wrapper (apt: faketime / libfaketime)

Usage:
    ft <host> <command> [args...]

Examples:
    ft dc.corp.local getTGT.py 'CORP.LOCAL/user:Password1'
    ft 10.10.10.100 evil-winrm -i 10.10.10.100 -r CORP.LOCAL
    ft dc.corp.local nxc ldap dc.corp.local -u user --use-kcache --users
"""

import math
import os
import re
import subprocess
import sys


def err(msg: str) -> None:
    print(msg, file=sys.stderr)


def main() -> None:
    if len(sys.argv) < 3:
        err("Usage: ft <host> <command> [args...]")
        sys.exit(1)

    host = sys.argv[1]
    cmd = sys.argv[2:]

    # Query the target's NTP time without actually syncing the clock.
    result = subprocess.run(
        ["ntpdate", "-q", host],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    ntp_out = result.stdout

    if result.returncode != 0:
        err("[!] ntpdate failed:")
        err(ntp_out)
        sys.exit(1)

    # Extract offset value — handles both formats:
    #   "offset +28799.123"
    #   "2026-... +28799.649 +/- ..."
    match = re.search(r'(?<=\s)[+-]?[0-9]{4,}\.[0-9]+', ntp_out)
    if not match:
        err("[!] Could not parse offset from ntpdate output:")
        err(ntp_out)
        sys.exit(1)

    offset_raw = float(match.group(0))

    # Round up to next whole hour, preserving sign.
    hours_int = math.ceil(abs(offset_raw) / 3600)
    hours = f"+{hours_int}h" if offset_raw >= 0 else f"-{hours_int}h"

    err(f"[*] Raw offset: {offset_raw}s  →  faketime: {hours}")
    err(f"[*] Running:    {' '.join(cmd)}")
    err("")

    # Replace the current process with faketime — identical to bash `exec faketime`.
    os.execvp("faketime", ["faketime", "-f", hours, *cmd])


if __name__ == "__main__":
    main()
