#!/usr/bin/env bash
# ft.sh - faketime wrapper that auto-calculates clock skew against a target host
#
# Requirements:
#   ntpdate   - clock sync query (apt: ntpdate)
#   faketime  - time spoofing wrapper (apt: faketime / libfaketime)
#   python3   - offset math
#
# Usage:
#   ft.sh <host> <command> [args...]
#
# Examples:
#   ft.sh dc.corp.local getTGT.py 'CORP.LOCAL/user:Password1'
#   ft.sh 10.10.10.100 evil-winrm -i 10.10.10.100 -r CORP.LOCAL
#   ft.sh dc.corp.local nxc ldap dc.corp.local -u user --use-kcache --users

HOST="${1:?Usage: ft.sh <host> <command> [args...]}"
shift

# ntpdate -q output: "server x.x.x.x, stratum N, offset +NNNNN.NNN, delay N.NNN"
NTP_OUT=$(ntpdate -q "$HOST" 2>&1)
if [[ $? -ne 0 ]]; then
    echo "[!] ntpdate failed:" >&2
    echo "$NTP_OUT" >&2
    exit 1
fi

# Extract offset value — handles both formats:
# "offset +28799.123" and "2026-... +28799.649 +/- ..."
OFFSET_RAW=$(echo "$NTP_OUT" | grep -oP '(?<=\s)[+-]?[0-9]{4,}\.[0-9]+' | head -1)

if [[ -z "$OFFSET_RAW" ]]; then
    echo "[!] Could not parse offset from ntpdate output:" >&2
    echo "$NTP_OUT" >&2
    exit 1
fi

# Round up to next whole hour, preserving sign
HOURS=$(python3 -c "
import math, sys
v = float('$OFFSET_RAW')
h = math.ceil(abs(v) / 3600)
print('+' + str(h) + 'h' if v >= 0 else '-' + str(h) + 'h')
")

echo "[*] Raw offset: ${OFFSET_RAW}s  →  faketime: ${HOURS}" >&2
echo "[*] Running:    $*" >&2
echo "" >&2

exec faketime -f "${HOURS}" "$@"