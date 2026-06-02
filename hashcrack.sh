#!/usr/bin/env bash
# hashcrack.sh - identify hash type and run hashcat with the correct mode
#
# Requirements:
#   hashcat  - password recovery tool (apt: hashcat)
#   python3  - hash identification logic
#
# Usage:
#   hashcrack.sh <hash_string_or_file>
#
# Note:
#   Pass a literal hash string or a path to a file containing one or more hashes.
#   Hash types that require binary input files (WPA .hccapx, TrueCrypt/VeraCrypt
#   containers, KeePass files, 1Password keychains, etc.) are not supported —
#   run hashcat directly for those.

# --- Configuration -----------------------------------------------------------
ROCKYOU="/usr/share/wordlists/rockyou.txt"
# -----------------------------------------------------------------------------

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

INPUT="${1:?Usage: hashcrack.sh <hash_string_or_file>}"

# Dependency checks
if ! command -v hashcat &>/dev/null; then
    printf "${RED}[!] hashcat not found in PATH${RESET}\n" >&2
    exit 1
fi

if [ ! -f "$ROCKYOU" ]; then
    printf "${RED}[!] rockyou.txt not found at: %s${RESET}\n" "$ROCKYOU" >&2
    printf "${RED}[!] Update the ROCKYOU variable at the top of this script${RESET}\n" >&2
    exit 1
fi

# Determine if input is a file or a literal hash string
HASH_FILE=""
CLEANUP_FILE=0

if [ -f "$INPUT" ]; then
    HASH_FILE="$INPUT"
    printf "${BLUE}[*] Using hash file: %s${RESET}\n" "$HASH_FILE" >&2
else
    # Write the literal string to a temp file
    HASH_FILE=$(mktemp /tmp/hashcrack.XXXXXX)
    CLEANUP_FILE=1
    printf '%s\n' "$INPUT" > "$HASH_FILE"
    printf "${BLUE}[*] Hash string written to temp file${RESET}\n" >&2
fi

# Clean up temp file on exit
trap '[ "$CLEANUP_FILE" -eq 1 ] && rm -f "$HASH_FILE"' EXIT

# Read the first non-empty line for identification purposes
SAMPLE_HASH=$(grep -m1 -v '^[[:space:]]*$' "$HASH_FILE" 2>/dev/null)
if [ -z "$SAMPLE_HASH" ]; then
    printf "${RED}[!] No hash found in input${RESET}\n" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Hash identification via Python
# Returns "MODE|NAME" or "AMBIGUOUS|candidate1|...|candidateN" or "UNKNOWN"
# ---------------------------------------------------------------------------
IDENT_RESULT=$(python3 - "$SAMPLE_HASH" <<'PY'
import re
import sys

h = sys.argv[1].strip()
hl = h.lower()

def is_hex(s, length=None):
    if length is not None and len(s) != length:
        return False
    return bool(re.match(r'^[0-9a-f]+$', s, re.IGNORECASE))

# ── Prefix-based (unambiguous) ──────────────────────────────────────────────

if re.match(r'^\$2[abyxA-Z]\$', h):
    print('3200|bcrypt')
elif h.startswith('$1$'):
    print('500|md5crypt ($1$)')
elif h.startswith('$apr1$'):
    print('1600|Apache apr1 md5crypt ($apr1$)')
elif h.startswith('$P$') or h.startswith('$H$'):
    print('400|phpass (WordPress/Joomla/phpBB3)')
elif h.startswith('$6$'):
    print('1800|sha512crypt ($6$)')
elif h.startswith('$5$'):
    print('7400|sha256crypt ($5$)')
elif h.startswith('$S$'):
    print('7900|Drupal7 ($S$)')
elif h.startswith('$shiro1$'):
    print('12150|Apache Shiro 1 (SHA-512)')
elif re.match(r'^\$krb5tgs\$23\$', h):
    print('13100|Kerberos 5 TGS-REP etype 23')
elif re.match(r'^\$krb5tgs\$', h):
    # Could be other etypes; 13100 is etype 23, most common
    print('13100|Kerberos 5 TGS-REP etype 23')
elif re.match(r'^\$krb5asrep\$23\$', h):
    print('18200|Kerberos 5 AS-REP etype 23')
elif re.match(r'^\$krb5asrep\$', h):
    print('18200|Kerberos 5 AS-REP etype 23')
elif re.match(r'^\$krb5pa\$23\$', h):
    print('7500|Kerberos 5 AS-REQ Pre-Auth etype 23')
elif h.startswith('$DCC2$'):
    print('2100|DCC2 / MS Cache 2 ($DCC2$)')
elif h.startswith('SCRYPT:'):
    print('8900|scrypt')
elif re.match(r'^\$8\$', h):
    print('9200|Cisco-IOS $8$ (PBKDF2-SHA256)')
elif re.match(r'^\$9\$', h):
    print('9300|Cisco-IOS $9$ (scrypt)')
elif h.startswith('grub.pbkdf2.sha512.'):
    print('7200|GRUB 2')
elif re.match(r'^\$office\$\*2007\*', h):
    print('9400|MS Office 2007')
elif re.match(r'^\$office\$\*2010\*', h):
    print('9500|MS Office 2010')
elif re.match(r'^\$office\$\*2013\*', h):
    print('9600|MS Office 2013')
elif re.match(r'^\$oldoffice\$[01]', h):
    print('9700|MS Office <= 2003 (MD5 + RC4)')
elif re.match(r'^\$oldoffice\$[34]', h):
    print('9800|MS Office <= 2003 (SHA1 + RC4)')
elif h.startswith('$rar5$'):
    print('13000|RAR5')
elif re.match(r'^\$RAR3\$', h):
    print('12500|RAR3-hp')
elif h.startswith('$zip2$'):
    print('13600|WinZip')
elif h.startswith('$7z$'):
    print('11600|7-Zip')
elif h.startswith('{smd5}'):
    print('6300|AIX {smd5}')
elif h.startswith('{ssha256}'):
    print('6400|AIX {ssha256}')
elif h.startswith('{ssha512}'):
    print('6500|AIX {ssha512}')
elif h.startswith('{ssha1}'):
    print('6700|AIX {ssha1}')
elif h.startswith('pbkdf2_sha256$'):
    print('10000|Django (PBKDF2-SHA256)')
elif re.match(r'^sha256:\d+:', h):
    print('10900|PBKDF2-HMAC-SHA256')
elif re.match(r'^md5:\d+:', h):
    print('11900|PBKDF2-HMAC-MD5')
elif re.match(r'^sha1:\d+:', h):
    print('12000|PBKDF2-HMAC-SHA1')
elif re.match(r'^sha512:\d+:', h):
    print('12100|PBKDF2-HMAC-SHA512')
elif h.startswith('$BLAKE2$'):
    print('600|BLAKE2b-512')
elif h.startswith('$cram_md5$'):
    print('10200|CRAM-MD5')
elif h.startswith('$postgres$'):
    print('11100|PostgreSQL CRAM (MD5)')
elif h.startswith('$mysqlna$'):
    print('11200|MySQL CRAM (SHA1)')
elif h.startswith('$sip$'):
    print('11400|SIP digest authentication (MD5)')
elif h.startswith('$racf$'):
    print('8500|RACF')
elif h.startswith('$ecryptfs$'):
    print('12200|eCryptfs')
elif h.startswith('0x') and is_hex(h[2:], 96):
    print('8000|Sybase ASE')
elif re.match(r'^\{x-issha,', h):
    print('10300|SAP CODVN H (PWDSALTEDHASH) iSSHA-1')
elif h.startswith('$keepass$*1*'):
    print('13400|KeePass 1 AES')
elif h.startswith('$keepass$*2*'):
    print('13400|KeePass 2 AES')
elif re.match(r'^\(G', h):
    print('8700|Lotus Notes/Domino 6')
elif re.match(r'^\(H', h):
    print('9100|Lotus Notes/Domino 8')
elif re.match(r'^\(I', h):
    print('9100|Lotus Notes/Domino 8')
elif h.startswith('AK1A') or re.match(r'^AK1[A-Z0-9+/]{3}', h):
    print('7000|FortiGate (FortiOS)')
elif h.startswith('{PBKDF2_SHA256}'):
    print('10901|RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)')
elif re.match(r'^\$axcrypt_sha1\$', h):
    print('13300|AxCrypt 1 in-memory SHA1')
elif re.match(r'^\$axcrypt\$', h):
    print('13200|AxCrypt 1')
elif re.match(r'^\$bitcoin\$', h):
    print('11300|Bitcoin/Litecoin wallet.dat')
elif re.match(r'^SCRYPT:', h):
    print('8900|scrypt')
elif re.match(r'^\$pdf\$', h):
    # Differentiate by version field
    m = re.match(r'^\$pdf\$(\d+)', h)
    if m:
        v = int(m.group(1))
        if v == 1:
            print('10400|PDF 1.1-1.3 (Acrobat 2-4)')
        elif v == 2:
            print('10500|PDF 1.4-1.6 (Acrobat 5-8)')
        elif v == 5:
            # Distinguish level 3 vs level 8 by the second field
            m2 = re.match(r'^\$pdf\$5\*(\d+)\*', h)
            if m2 and int(m2.group(1)) == 6:
                print('10700|PDF 1.7 Level 8 (Acrobat 10-11)')
            else:
                print('10600|PDF 1.7 Level 3 (Acrobat 9)')
        else:
            print('10500|PDF (Acrobat)')
    else:
        print('10400|PDF')
elif re.match(r'^\$blockchain\$', h):
    print('12700|Blockchain My Wallet')

# ── Structural / field-format ────────────────────────────────────────────────

# NetNTLMv2: user::domain:challenge:response:blob (6 colon-separated fields,
# challenge is 16 hex, response is 32 hex)
elif re.match(
    r'^[^:]+::[^:]*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$', h, re.IGNORECASE
):
    print('5600|NetNTLMv2')

# NetNTLMv1: user::domain:LMResponse:NTResponse:challenge
# LMResponse = 48 hex, NTResponse = 48 hex, challenge = 16 hex
elif re.match(
    r'^[^:]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$', h, re.IGNORECASE
):
    print('5500|NetNTLMv1 / NetNTLMv1+ESS')

# DCC / MS Cache: 32hex:username
elif re.match(r'^[0-9a-f]{32}:[^:]+$', h, re.IGNORECASE) and not h.startswith('$'):
    parts = h.split(':')
    # Salt part is non-hex (username), not a pure number → DCC
    if not is_hex(parts[1]):
        print('1100|DCC / MS Cache (domain:username)')
    else:
        print('AMBIGUOUS|10|md5($pass.$salt) mode 10|20|md5($salt.$pass) mode 20')

# IPMI2 RAKP HMAC-SHA1: long_hex:long_hex
elif re.match(r'^[0-9a-f]{40,}:[0-9a-f]{40,}$', h, re.IGNORECASE):
    parts = h.split(':')
    if len(parts[0]) == 40 and len(parts[1]) >= 40:
        print('7300|IPMI2 RAKP HMAC-SHA1')
    else:
        print('UNKNOWN')

# Oracle H: HASH:SALT (16 uppercase hex : 10 digit number)
elif re.match(r'^[0-9A-F]{16}:[0-9]{10}$', h):
    print('3100|Oracle H: Type (Oracle 7+)')

# DNSSEC NSEC3: hash.label:zone:iterations:salt
elif re.match(r'^[0-9a-z]+\.[a-z0-9.-]+:\d+:\d+$', h, re.IGNORECASE):
    print('8300|DNSSEC (NSEC3)')

# Kerberos 5 AS-REQ Pre-Auth (alternate format without $krb5pa$)
elif re.match(r'^\$krb5pa\$', h):
    print('7500|Kerberos 5 AS-REQ Pre-Auth')

# CRC32: 8hex:8hex
elif re.match(r'^[0-9a-f]{8}:[0-9a-f]{8}$', h, re.IGNORECASE):
    print('11500|CRC32')

# SipHash: hex:2:4:hex
elif re.match(r'^[0-9a-f]+:2:4:[0-9a-f]+$', h, re.IGNORECASE):
    print('10100|SipHash')

# Samsung Android PIN: 40hex:8hex
elif re.match(r'^[0-9a-f]{40}:[0-9a-f]{8}$', h, re.IGNORECASE):
    print('5800|Samsung Android Password/PIN')

# Citrix NetScaler SHA1: starts with '1765', 50 hex chars
elif re.match(r'^1765[0-9a-f]{46}$', h, re.IGNORECASE):
    print('8100|Citrix NetScaler (SHA1)')

# SAP CODVN B (BCODE): USER$HASH
elif re.match(r'^[A-Z0-9]+\$[0-9A-F]{16}$', h):
    print('7700|SAP CODVN B (BCODE)')

# SAP CODVN F/G (PASSCODE): USER$HASH (40 hex)
elif re.match(r'^[A-Z0-9]+\$[0-9A-F]{40}$', h):
    print('7800|SAP CODVN F/G (PASSCODE)')

# BSDi Crypt: starts with underscore, 20 chars
elif re.match(r'^_[./0-9A-Za-z]{19}$', h):
    print('12400|BSDi Crypt / Extended DES')

# Traditional DES crypt: 13-char [a-zA-Z0-9./]
elif re.match(r'^[./0-9A-Za-z]{13}$', h):
    print('1500|descrypt / DES (Unix) / Traditional DES')

# Cisco-PIX MD5: exactly 16 chars, alphanumeric (base64-ish, no padding)
elif re.match(r'^[./0-9A-Za-z]{16}$', h) and not is_hex(h):
    print('2400|Cisco-PIX MD5')

# Cisco-ASA MD5: short_hash:number
elif re.match(r'^[./0-9A-Za-z]{14,18}:\d+$', h) and not is_hex(h.split(':')[0]):
    print('2410|Cisco-ASA MD5')

# Cisco-IOS type 4 SHA256: 43-char base64 (no padding '=')
elif re.match(r'^[0-9A-Za-z+/]{43}$', h):
    print('5700|Cisco-IOS type 4 (SHA256)')

# FortiGate: base64 with padding ending in '='
elif re.match(r'^[0-9A-Za-z+/]+=+$', h) and len(h) > 30:
    print('7000|FortiGate (FortiOS)')

# GOST R 34.11-94: 64 hex (same length as SHA-256, distinguish by context — note ambiguity)
# Handled in length-ambiguous block below.

# ── Length-based hex (potentially ambiguous) ─────────────────────────────────

elif is_hex(h):
    length = len(h)
    if length == 8:
        print('11500|CRC32 (half)')
    elif length == 16:
        print('AMBIGUOUS|5100|Half MD5|3000|LM|200|MySQL323')
    elif length == 32:
        print('AMBIGUOUS|0|MD5|1000|NTLM|900|MD4')
    elif length == 40:
        print('AMBIGUOUS|100|SHA1|6000|RIPEMD-160|300|MySQL4.1/MySQL5')
    elif length == 48:
        print('1300|SHA2-224')
    elif length == 56:
        print('1300|SHA2-224')
    elif length == 64:
        print('AMBIGUOUS|1400|SHA2-256|11700|GOST R 34.11-2012 256-bit')
    elif length == 96:
        print('10800|SHA2-384')
    elif length == 128:
        print('AMBIGUOUS|1700|SHA2-512|11800|GOST R 34.11-2012 512-bit|6100|Whirlpool')
    elif length == 160:
        print('12300|Oracle T: Type (Oracle 12+)')
    else:
        print('UNKNOWN')

else:
    print('UNKNOWN')
PY
)

if [ -z "$IDENT_RESULT" ]; then
    printf "${RED}[!] Hash identification failed${RESET}\n" >&2
    exit 1
fi

# Parse the result
IDENT_TYPE=$(printf '%s' "$IDENT_RESULT" | cut -d'|' -f1)

# ── Handle UNKNOWN ────────────────────────────────────────────────────────────
if [ "$IDENT_TYPE" = "UNKNOWN" ]; then
    printf "${RED}[!] Could not identify hash type${RESET}\n" >&2
    printf "${YELLOW}[*] Sample: %s${RESET}\n" "$SAMPLE_HASH" >&2
    printf "${YELLOW}[*] Specify the mode manually: hashcat -m <mode> %s %s${RESET}\n" \
        "$HASH_FILE" "$ROCKYOU" >&2
    exit 1
fi

# ── Handle AMBIGUOUS ─────────────────────────────────────────────────────────
if [ "$IDENT_TYPE" = "AMBIGUOUS" ]; then
    # Parse candidates: AMBIGUOUS|mode1|name1|mode2|name2|...
    # Fields: 2=mode1, 3=name1, 4=mode2, 5=name2, ...
    IFS='|' read -ra PARTS <<< "$IDENT_RESULT"
    # PARTS[0]=AMBIGUOUS, then pairs: PARTS[1]=mode, PARTS[2]=name, ...
    NUM_CANDIDATES=$(( (${#PARTS[@]} - 1) / 2 ))

    echo "" >&2
    printf "${YELLOW}[*] Ambiguous hash — multiple possible types:${RESET}\n" >&2
    echo "" >&2

    idx=1
    for (( i=1; i<${#PARTS[@]}; i+=2 )); do
        MODE_CAND="${PARTS[$i]}"
        NAME_CAND="${PARTS[$((i+1))]}"
        printf "  ${YELLOW}[%d]${RESET} %-6s  %s\n" "$idx" "$MODE_CAND" "$NAME_CAND" >&2
        idx=$((idx + 1))
    done

    echo "" >&2
    printf "  ${YELLOW}[q]${RESET} Quit\n" >&2
    echo "" >&2
    printf "  Select type: " >&2

    if ! IFS= read -r choice; then
        printf "\n${YELLOW}[*] Aborted.${RESET}\n" >&2
        exit 0
    fi

    if [ "$choice" = "q" ] || [ "$choice" = "Q" ]; then
        printf "${YELLOW}[*] Aborted.${RESET}\n" >&2
        exit 0
    fi

    case "$choice" in
        ''|*[!0-9]*)
            printf "${RED}[!] Invalid selection.${RESET}\n" >&2
            exit 1
            ;;
    esac

    if [ "$choice" -lt 1 ] || [ "$choice" -gt "$NUM_CANDIDATES" ]; then
        printf "${RED}[!] Invalid selection.${RESET}\n" >&2
        exit 1
    fi

    # Pull out the chosen mode/name pair
    PAIR_IDX=$(( (choice - 1) * 2 + 1 ))
    HASHCAT_MODE="${PARTS[$PAIR_IDX]}"
    HASH_NAME="${PARTS[$((PAIR_IDX + 1))]}"
else
    # Unambiguous: MODE|NAME
    HASHCAT_MODE="$IDENT_TYPE"
    HASH_NAME=$(printf '%s' "$IDENT_RESULT" | cut -d'|' -f2-)
fi

# ── Run hashcat ───────────────────────────────────────────────────────────────
echo "" >&2
printf "${GREEN}[+] Identified:  %s (mode %s)${RESET}\n" "$HASH_NAME" "$HASHCAT_MODE" >&2
printf "${BLUE}[*] Wordlist:    %s${RESET}\n" "$ROCKYOU" >&2
printf "${BLUE}[*] Command:     hashcat -m %s %s %s${RESET}\n" \
    "$HASHCAT_MODE" "$HASH_FILE" "$ROCKYOU" >&2
echo "" >&2

hashcat -m "$HASHCAT_MODE" "$HASH_FILE" "$ROCKYOU"
HC_EXIT=$?

echo "" >&2
if [ $HC_EXIT -eq 0 ]; then
    printf "${GREEN}[+] hashcat finished successfully${RESET}\n" >&2
elif [ $HC_EXIT -eq 1 ]; then
    printf "${RED}[!] hashcat encountered a fatal error${RESET}\n" >&2
else
    # Exit code 2 = exhausted, 3 = aborted — still informative
    printf "${YELLOW}[*] hashcat exited with code %d${RESET}\n" "$HC_EXIT" >&2
fi

exit $HC_EXIT
