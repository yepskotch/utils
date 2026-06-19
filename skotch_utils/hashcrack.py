#!/usr/bin/env python3
"""hashcrack - identify hash type and run hashcat with the correct mode.

Requirements:
    hashcat  - password recovery tool (apt: hashcat)

Usage:
    hashcrack [--wordlist PATH] <hash_string_or_file>

Note:
    Pass a literal hash string or a path to a file containing one or more hashes.
    Hash types that require binary input files (WPA .hccapx, TrueCrypt/VeraCrypt
    containers, KeePass files, 1Password keychains, etc.) are not supported —
    run hashcat directly for those.
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
BLUE   = '\033[0;34m'
YELLOW = '\033[0;33m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

DEFAULT_ROCKYOU = "/usr/share/wordlists/rockyou.txt"


def err(msg: str = "") -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------------------
# Hash identification
# Returns one of:
#   ("unambiguous", mode_str, name_str)
#   ("ambiguous",   [(mode_str, name_str), ...])
#   ("unknown",     None, None)
# ---------------------------------------------------------------------------
def identify_hash(h: str):
    hl = h.lower()

    def is_hex(s, length=None):
        if length is not None and len(s) != length:
            return False
        return bool(re.match(r'^[0-9a-f]+$', s, re.IGNORECASE))

    def unambiguous(mode, name):
        return ("unambiguous", str(mode), name)

    def ambiguous(*candidates):
        # candidates: list of (mode, name) tuples
        return ("ambiguous", list(candidates))

    def unknown():
        return ("unknown", None, None)

    # ── Prefix-based (unambiguous) ──────────────────────────────────────────

    if re.match(r'^\$2[abyxA-Z]\$', h):
        return unambiguous(3200, "bcrypt")
    if h.startswith('$1$'):
        return unambiguous(500, "md5crypt ($1$)")
    if h.startswith('$apr1$'):
        return unambiguous(1600, "Apache apr1 md5crypt ($apr1$)")
    if h.startswith('$P$') or h.startswith('$H$'):
        return unambiguous(400, "phpass (WordPress/Joomla/phpBB3)")
    if h.startswith('$6$'):
        return unambiguous(1800, "sha512crypt ($6$)")
    if h.startswith('$5$'):
        return unambiguous(7400, "sha256crypt ($5$)")
    if h.startswith('$S$'):
        return unambiguous(7900, "Drupal7 ($S$)")
    if h.startswith('$shiro1$'):
        return unambiguous(12150, "Apache Shiro 1 (SHA-512)")
    if re.match(r'^\$krb5tgs\$23\$', h):
        return unambiguous(13100, "Kerberos 5 TGS-REP etype 23")
    if re.match(r'^\$krb5tgs\$', h):
        return unambiguous(13100, "Kerberos 5 TGS-REP etype 23")
    if re.match(r'^\$krb5asrep\$23\$', h):
        return unambiguous(18200, "Kerberos 5 AS-REP etype 23")
    if re.match(r'^\$krb5asrep\$', h):
        return unambiguous(18200, "Kerberos 5 AS-REP etype 23")
    if re.match(r'^\$krb5pa\$23\$', h):
        return unambiguous(7500, "Kerberos 5 AS-REQ Pre-Auth etype 23")
    if h.startswith('$DCC2$'):
        return unambiguous(2100, "DCC2 / MS Cache 2 ($DCC2$)")
    if h.startswith('SCRYPT:'):
        return unambiguous(8900, "scrypt")
    if re.match(r'^\$8\$', h):
        return unambiguous(9200, "Cisco-IOS $8$ (PBKDF2-SHA256)")
    if re.match(r'^\$9\$', h):
        return unambiguous(9300, "Cisco-IOS $9$ (scrypt)")
    if h.startswith('grub.pbkdf2.sha512.'):
        return unambiguous(7200, "GRUB 2")
    if re.match(r'^\$office\$\*2007\*', h):
        return unambiguous(9400, "MS Office 2007")
    if re.match(r'^\$office\$\*2010\*', h):
        return unambiguous(9500, "MS Office 2010")
    if re.match(r'^\$office\$\*2013\*', h):
        return unambiguous(9600, "MS Office 2013")
    if re.match(r'^\$oldoffice\$[01]', h):
        return unambiguous(9700, "MS Office <= 2003 (MD5 + RC4)")
    if re.match(r'^\$oldoffice\$[34]', h):
        return unambiguous(9800, "MS Office <= 2003 (SHA1 + RC4)")
    if h.startswith('$rar5$'):
        return unambiguous(13000, "RAR5")
    if re.match(r'^\$RAR3\$', h):
        return unambiguous(12500, "RAR3-hp")
    if h.startswith('$zip2$'):
        return unambiguous(13600, "WinZip")
    if h.startswith('$7z$'):
        return unambiguous(11600, "7-Zip")
    if h.startswith('{smd5}'):
        return unambiguous(6300, "AIX {smd5}")
    if h.startswith('{ssha256}'):
        return unambiguous(6400, "AIX {ssha256}")
    if h.startswith('{ssha512}'):
        return unambiguous(6500, "AIX {ssha512}")
    if h.startswith('{ssha1}'):
        return unambiguous(6700, "AIX {ssha1}")
    if h.startswith('pbkdf2_sha256$'):
        return unambiguous(10000, "Django (PBKDF2-SHA256)")
    if re.match(r'^sha256:\d+:', h):
        return unambiguous(10900, "PBKDF2-HMAC-SHA256")
    if re.match(r'^md5:\d+:', h):
        return unambiguous(11900, "PBKDF2-HMAC-MD5")
    if re.match(r'^sha1:\d+:', h):
        return unambiguous(12000, "PBKDF2-HMAC-SHA1")
    if re.match(r'^sha512:\d+:', h):
        return unambiguous(12100, "PBKDF2-HMAC-SHA512")
    if h.startswith('$BLAKE2$'):
        return unambiguous(600, "BLAKE2b-512")
    if h.startswith('$cram_md5$'):
        return unambiguous(10200, "CRAM-MD5")
    if h.startswith('$postgres$'):
        return unambiguous(11100, "PostgreSQL CRAM (MD5)")
    if h.startswith('$mysqlna$'):
        return unambiguous(11200, "MySQL CRAM (SHA1)")
    if h.startswith('$sip$'):
        return unambiguous(11400, "SIP digest authentication (MD5)")
    if h.startswith('$racf$'):
        return unambiguous(8500, "RACF")
    if h.startswith('$ecryptfs$'):
        return unambiguous(12200, "eCryptfs")
    if h.startswith('0x') and is_hex(h[2:], 96):
        return unambiguous(8000, "Sybase ASE")
    if re.match(r'^\{x-issha,', h):
        return unambiguous(10300, "SAP CODVN H (PWDSALTEDHASH) iSSHA-1")
    if h.startswith('$keepass$*1*'):
        return unambiguous(13400, "KeePass 1 AES")
    if h.startswith('$keepass$*2*'):
        return unambiguous(13400, "KeePass 2 AES")
    if re.match(r'^\(G', h):
        return unambiguous(8700, "Lotus Notes/Domino 6")
    if re.match(r'^\(H', h):
        return unambiguous(9100, "Lotus Notes/Domino 8")
    if re.match(r'^\(I', h):
        return unambiguous(9100, "Lotus Notes/Domino 8")
    if h.startswith('AK1A') or re.match(r'^AK1[A-Z0-9+/]{3}', h):
        return unambiguous(7000, "FortiGate (FortiOS)")
    if h.startswith('{PBKDF2_SHA256}'):
        return unambiguous(10901, "RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)")
    if re.match(r'^\$axcrypt_sha1\$', h):
        return unambiguous(13300, "AxCrypt 1 in-memory SHA1")
    if re.match(r'^\$axcrypt\$', h):
        return unambiguous(13200, "AxCrypt 1")
    if re.match(r'^\$bitcoin\$', h):
        return unambiguous(11300, "Bitcoin/Litecoin wallet.dat")
    if re.match(r'^SCRYPT:', h):
        return unambiguous(8900, "scrypt")
    if re.match(r'^\$pdf\$', h):
        m = re.match(r'^\$pdf\$(\d+)', h)
        if m:
            v = int(m.group(1))
            if v == 1:
                return unambiguous(10400, "PDF 1.1-1.3 (Acrobat 2-4)")
            elif v == 2:
                return unambiguous(10500, "PDF 1.4-1.6 (Acrobat 5-8)")
            elif v == 5:
                m2 = re.match(r'^\$pdf\$5\*(\d+)\*', h)
                if m2 and int(m2.group(1)) == 6:
                    return unambiguous(10700, "PDF 1.7 Level 8 (Acrobat 10-11)")
                else:
                    return unambiguous(10600, "PDF 1.7 Level 3 (Acrobat 9)")
            else:
                return unambiguous(10500, "PDF (Acrobat)")
        else:
            return unambiguous(10400, "PDF")
    if re.match(r'^\$blockchain\$', h):
        return unambiguous(12700, "Blockchain My Wallet")

    # ── Structural / field-format ────────────────────────────────────────────

    # NetNTLMv2
    if re.match(r'^[^:]+::[^:]*:[0-9a-f]{16}:[0-9a-f]{32}:[0-9a-f]+$', h, re.IGNORECASE):
        return unambiguous(5600, "NetNTLMv2")

    # NetNTLMv1
    if re.match(r'^[^:]+::[^:]*:[0-9a-f]{48}:[0-9a-f]{48}:[0-9a-f]{16}$', h, re.IGNORECASE):
        return unambiguous(5500, "NetNTLMv1 / NetNTLMv1+ESS")

    # DCC / MS Cache: 32hex:username
    if re.match(r'^[0-9a-f]{32}:[^:]+$', h, re.IGNORECASE) and not h.startswith('$'):
        parts = h.split(':')
        if not is_hex(parts[1]):
            return unambiguous(1100, "DCC / MS Cache (domain:username)")
        else:
            return ambiguous(("10", "md5($pass.$salt) mode 10"), ("20", "md5($salt.$pass) mode 20"))

    # IPMI2 RAKP HMAC-SHA1
    if re.match(r'^[0-9a-f]{40,}:[0-9a-f]{40,}$', h, re.IGNORECASE):
        parts = h.split(':')
        if len(parts[0]) == 40 and len(parts[1]) >= 40:
            return unambiguous(7300, "IPMI2 RAKP HMAC-SHA1")
        else:
            return unknown()

    # Oracle H:
    if re.match(r'^[0-9A-F]{16}:[0-9]{10}$', h):
        return unambiguous(3100, "Oracle H: Type (Oracle 7+)")

    # DNSSEC NSEC3
    if re.match(r'^[0-9a-z]+\.[a-z0-9.-]+:\d+:\d+$', h, re.IGNORECASE):
        return unambiguous(8300, "DNSSEC (NSEC3)")

    # Kerberos 5 AS-REQ Pre-Auth (alternate format)
    if re.match(r'^\$krb5pa\$', h):
        return unambiguous(7500, "Kerberos 5 AS-REQ Pre-Auth")

    # CRC32: 8hex:8hex
    if re.match(r'^[0-9a-f]{8}:[0-9a-f]{8}$', h, re.IGNORECASE):
        return unambiguous(11500, "CRC32")

    # SipHash
    if re.match(r'^[0-9a-f]+:2:4:[0-9a-f]+$', h, re.IGNORECASE):
        return unambiguous(10100, "SipHash")

    # Samsung Android PIN: 40hex:8hex
    if re.match(r'^[0-9a-f]{40}:[0-9a-f]{8}$', h, re.IGNORECASE):
        return unambiguous(5800, "Samsung Android Password/PIN")

    # Citrix NetScaler SHA1
    if re.match(r'^1765[0-9a-f]{46}$', h, re.IGNORECASE):
        return unambiguous(8100, "Citrix NetScaler (SHA1)")

    # SAP CODVN B (BCODE)
    if re.match(r'^[A-Z0-9]+\$[0-9A-F]{16}$', h):
        return unambiguous(7700, "SAP CODVN B (BCODE)")

    # SAP CODVN F/G (PASSCODE)
    if re.match(r'^[A-Z0-9]+\$[0-9A-F]{40}$', h):
        return unambiguous(7800, "SAP CODVN F/G (PASSCODE)")

    # BSDi Crypt
    if re.match(r'^_[./0-9A-Za-z]{19}$', h):
        return unambiguous(12400, "BSDi Crypt / Extended DES")

    # Traditional DES crypt: 13-char
    if re.match(r'^[./0-9A-Za-z]{13}$', h):
        return unambiguous(1500, "descrypt / DES (Unix) / Traditional DES")

    # Cisco-PIX MD5: 16 chars, not pure hex
    if re.match(r'^[./0-9A-Za-z]{16}$', h) and not is_hex(h):
        return unambiguous(2400, "Cisco-PIX MD5")

    # Cisco-ASA MD5
    if re.match(r'^[./0-9A-Za-z]{14,18}:\d+$', h) and not is_hex(h.split(':')[0]):
        return unambiguous(2410, "Cisco-ASA MD5")

    # Cisco-IOS type 4 SHA256: 43-char base64 (no padding)
    if re.match(r'^[0-9A-Za-z+/]{43}$', h):
        return unambiguous(5700, "Cisco-IOS type 4 (SHA256)")

    # FortiGate: base64 with padding
    if re.match(r'^[0-9A-Za-z+/]+=+$', h) and len(h) > 30:
        return unambiguous(7000, "FortiGate (FortiOS)")

    # ── Length-based hex (potentially ambiguous) ─────────────────────────────

    if is_hex(h):
        length = len(h)
        if length == 8:
            return unambiguous(11500, "CRC32 (half)")
        elif length == 16:
            return ambiguous(("5100", "Half MD5"), ("3000", "LM"), ("200", "MySQL323"))
        elif length == 32:
            return ambiguous(("0", "MD5"), ("1000", "NTLM"), ("900", "MD4"))
        elif length == 40:
            return ambiguous(("100", "SHA1"), ("6000", "RIPEMD-160"), ("300", "MySQL4.1/MySQL5"))
        elif length == 48:
            return unambiguous(1300, "SHA2-224")
        elif length == 56:
            return unambiguous(1300, "SHA2-224")
        elif length == 64:
            return ambiguous(("1400", "SHA2-256"), ("11700", "GOST R 34.11-2012 256-bit"))
        elif length == 96:
            return unambiguous(10800, "SHA2-384")
        elif length == 128:
            return ambiguous(("1700", "SHA2-512"), ("11800", "GOST R 34.11-2012 512-bit"), ("6100", "Whirlpool"))
        elif length == 160:
            return unambiguous(12300, "Oracle T: Type (Oracle 12+)")
        else:
            return unknown()

    return unknown()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hashcrack",
        description="Identify hash type and run hashcat with the correct mode.",
        epilog="Pass a literal hash string or a path to a file containing one or more hashes.",
    )
    parser.add_argument("input", help="Hash string or path to a file containing hashes")
    parser.add_argument(
        "-w", "--wordlist",
        default=DEFAULT_ROCKYOU,
        metavar="PATH",
        help=f"Path to wordlist (default: {DEFAULT_ROCKYOU})",
    )
    args = parser.parse_args()

    # Dependency checks
    if not any(
        os.access(os.path.join(d, "hashcat"), os.X_OK)
        for d in os.environ.get("PATH", "").split(os.pathsep)
    ):
        err(f"{RED}[!] hashcat not found in PATH{RESET}")
        sys.exit(1)

    if not os.path.isfile(args.wordlist):
        err(f"{RED}[!] wordlist not found at: {args.wordlist}{RESET}")
        err(f"{RED}[!] Use -w / --wordlist to specify a different path{RESET}")
        sys.exit(1)

    # Determine if input is a file or a literal hash string
    tmp_path = None
    if os.path.isfile(args.input):
        hash_file = args.input
        err(f"{BLUE}[*] Using hash file: {hash_file}{RESET}")
    else:
        fd, tmp_path = tempfile.mkstemp(prefix="hashcrack.")
        with os.fdopen(fd, "w") as f:
            f.write(args.input + "\n")
        hash_file = tmp_path
        err(f"{BLUE}[*] Hash string written to temp file{RESET}")

    try:
        # Read first non-empty line for identification
        sample_hash = ""
        with open(hash_file) as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    sample_hash = stripped
                    break

        if not sample_hash:
            err(f"{RED}[!] No hash found in input{RESET}")
            sys.exit(1)

        # Identify hash type
        result = identify_hash(sample_hash)
        kind = result[0]

        if kind == "unknown":
            err(f"{RED}[!] Could not identify hash type{RESET}")
            err(f"{YELLOW}[*] Sample: {sample_hash}{RESET}")
            err(f"{YELLOW}[*] Specify the mode manually: hashcat -m <mode> {hash_file} {args.wordlist}{RESET}")
            sys.exit(1)

        if kind == "ambiguous":
            candidates = result[1]  # list of (mode, name)
            err("")
            err(f"{YELLOW}[*] Ambiguous hash — multiple possible types:{RESET}")
            err("")
            for idx, (mode, name) in enumerate(candidates, start=1):
                err(f"  {YELLOW}[{idx}]{RESET} {mode:<6}  {name}")
            err("")
            err(f"  {YELLOW}[q]{RESET} Quit")
            err("")

            try:
                choice_raw = input("  Select type: ").strip()
            except (EOFError, KeyboardInterrupt):
                err(f"\n{YELLOW}[*] Aborted.{RESET}")
                sys.exit(0)

            if choice_raw.lower() == "q":
                err(f"{YELLOW}[*] Aborted.{RESET}")
                sys.exit(0)

            if not choice_raw.isdigit():
                err(f"{RED}[!] Invalid selection.{RESET}")
                sys.exit(1)

            choice = int(choice_raw)
            if choice < 1 or choice > len(candidates):
                err(f"{RED}[!] Invalid selection.{RESET}")
                sys.exit(1)

            hashcat_mode, hash_name = candidates[choice - 1]
        else:
            # unambiguous: ("unambiguous", mode_str, name_str)
            hashcat_mode = result[1]
            hash_name = result[2]

        # Run hashcat
        err("")
        err(f"{GREEN}[+] Identified:  {hash_name} (mode {hashcat_mode}){RESET}")
        err(f"{BLUE}[*] Wordlist:    {args.wordlist}{RESET}")
        err(f"{BLUE}[*] Command:     hashcat -m {hashcat_mode} {hash_file} {args.wordlist}{RESET}")
        err("")

        hc = subprocess.run(["hashcat", "-m", str(hashcat_mode), hash_file, args.wordlist])

        err("")
        if hc.returncode == 0:
            err(f"{GREEN}[+] hashcat finished successfully{RESET}")
        elif hc.returncode == 1:
            err(f"{RED}[!] hashcat encountered a fatal error{RESET}")
        else:
            err(f"{YELLOW}[*] hashcat exited with code {hc.returncode}{RESET}")

        sys.exit(hc.returncode)

    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


if __name__ == "__main__":
    main()
