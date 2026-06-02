# utils

Personal offensive utility scripts. Provided as-is with no guarantees — review before use in any environment you care about.

---

## ft.sh

Wraps a command with `faketime` after automatically calculating the clock skew against a target host. Useful when attacking Kerberos environments where your system clock differs from the DC.

**Requirements:** `ntpdate`, `faketime` (apt: `faketime`), `python3`

**Usage:**
```
ft.sh <host> <command> [args...]
```

**Examples:**
```bash
ft.sh dc.corp.local getTGT.py 'CORP.LOCAL/user:Password1'
ft.sh 10.10.10.100 evil-winrm -i 10.10.10.100 -r CORP.LOCAL
ft.sh dc.corp.local nxc ldap dc.corp.local -u user --use-kcache --users
```

Queries the target with `ntpdate`, extracts the offset, rounds up to the nearest whole hour, and passes it to `faketime -f`.

---

## klist-pick.sh

Interactive menu to select a `.ccache` file from the current directory, preview its tickets with `klist`, and export it as `KRB5CCNAME`.

**Requirements:** `klist` (apt: `krb5-user`), `python3`

**Usage:**
```bash
source klist-pick.sh
```

Must be sourced for the `export KRB5CCNAME=` to take effect in the current shell.

**Features:**
- Lists all `.ccache` files in the current directory with their default principal
- Shows the currently active `KRB5CCNAME` if already set
- Previews ticket details via `klist` before committing
- Warns if the selected ticket is expired

---

## hashcrack.sh

Identifies a hash type and runs hashcat against it with the correct mode using the rockyou wordlist.

**Requirements:** `hashcat`, `python3`

**Usage:**
```
hashcrack.sh <hash_string_or_file>
```

Pass a literal hash string or a path to a file containing one or more hashes. The rockyou.txt path is configured via the `ROCKYOU` variable at the top of the script (default: `/usr/share/wordlists/rockyou.txt`).

**Examples:**
```bash
hashcrack.sh 8743b52063cd84097a65d1633f5c74f5
hashcrack.sh '$6$qdMgClgO2dQWB37F$jhexCX1SdsCAi0OZmoRVAPnWSwuP...'
hashcrack.sh '$krb5tgs$23$*user$realm$test/spn*$...'
hashcrack.sh hashes.txt
```

**Supported hash types (auto-detected):**

| Mode | Name |
|------|------|
| 0 | MD5 *(interactive — ambiguous with NTLM, MD4)* |
| 100 | SHA1 *(interactive — ambiguous with RIPEMD-160, MySQL4.1)* |
| 200 | MySQL323 *(interactive — ambiguous with Half-MD5, LM)* |
| 300 | MySQL4.1/MySQL5 *(interactive)* |
| 400 | phpass (WordPress/Joomla/phpBB3) |
| 500 | md5crypt (`$1$`) |
| 600 | BLAKE2b-512 |
| 900 | MD4 *(interactive)* |
| 1000 | NTLM *(interactive)* |
| 1100 | DCC / MS Cache |
| 1300 | SHA2-224 |
| 1400 | SHA2-256 *(interactive — ambiguous with GOST 256-bit)* |
| 1500 | descrypt / Traditional DES |
| 1600 | Apache apr1 md5crypt |
| 1700 | SHA2-512 *(interactive — ambiguous with GOST 512-bit, Whirlpool)* |
| 1800 | sha512crypt (`$6$`) |
| 2100 | DCC2 / MS Cache 2 |
| 2400 | Cisco-PIX MD5 |
| 2410 | Cisco-ASA MD5 |
| 3000 | LM *(interactive)* |
| 3100 | Oracle H: Type (Oracle 7+) |
| 3200 | bcrypt |
| 5100 | Half MD5 *(interactive)* |
| 5500 | NetNTLMv1 / NetNTLMv1+ESS |
| 5600 | NetNTLMv2 |
| 5700 | Cisco-IOS type 4 (SHA256) |
| 5800 | Samsung Android Password/PIN |
| 6000 | RIPEMD-160 *(interactive)* |
| 6100 | Whirlpool *(interactive)* |
| 6300 | AIX `{smd5}` |
| 6400 | AIX `{ssha256}` |
| 6500 | AIX `{ssha512}` |
| 6700 | AIX `{ssha1}` |
| 7000 | FortiGate (FortiOS) |
| 7200 | GRUB 2 |
| 7300 | IPMI2 RAKP HMAC-SHA1 |
| 7400 | sha256crypt (`$5$`) |
| 7500 | Kerberos 5 AS-REQ Pre-Auth etype 23 |
| 7700 | SAP CODVN B (BCODE) |
| 7800 | SAP CODVN F/G (PASSCODE) |
| 7900 | Drupal7 (`$S$`) |
| 8000 | Sybase ASE |
| 8100 | Citrix NetScaler (SHA1) |
| 8300 | DNSSEC (NSEC3) |
| 8500 | RACF |
| 8700 | Lotus Notes/Domino 6 |
| 8800 | scrypt |
| 8900 | scrypt (`SCRYPT:`) |
| 9100 | Lotus Notes/Domino 8 |
| 9200 | Cisco-IOS `$8$` (PBKDF2-SHA256) |
| 9300 | Cisco-IOS `$9$` (scrypt) |
| 9400 | MS Office 2007 |
| 9500 | MS Office 2010 |
| 9600 | MS Office 2013 |
| 9700 | MS Office <= 2003 (MD5 + RC4) |
| 9800 | MS Office <= 2003 (SHA1 + RC4) |
| 10000 | Django (PBKDF2-SHA256) |
| 10100 | SipHash |
| 10200 | CRAM-MD5 |
| 10300 | SAP CODVN H (PWDSALTEDHASH) iSSHA-1 |
| 10400 | PDF 1.1-1.3 (Acrobat 2-4) |
| 10500 | PDF 1.4-1.6 (Acrobat 5-8) |
| 10600 | PDF 1.7 Level 3 (Acrobat 9) |
| 10700 | PDF 1.7 Level 8 (Acrobat 10-11) |
| 10800 | SHA2-384 |
| 10900 | PBKDF2-HMAC-SHA256 |
| 10901 | RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256) |
| 11100 | PostgreSQL CRAM (MD5) |
| 11200 | MySQL CRAM (SHA1) |
| 11300 | Bitcoin/Litecoin wallet.dat |
| 11400 | SIP digest authentication (MD5) |
| 11500 | CRC32 |
| 11600 | 7-Zip |
| 11700 | GOST R 34.11-2012 256-bit *(interactive)* |
| 11800 | GOST R 34.11-2012 512-bit *(interactive)* |
| 11900 | PBKDF2-HMAC-MD5 |
| 12000 | PBKDF2-HMAC-SHA1 |
| 12100 | PBKDF2-HMAC-SHA512 |
| 12150 | Apache Shiro 1 (SHA-512) |
| 12200 | eCryptfs |
| 12300 | Oracle T: Type (Oracle 12+) |
| 12400 | BSDi Crypt / Extended DES |
| 12500 | RAR3-hp |
| 12700 | Blockchain My Wallet |
| 13000 | RAR5 |
| 13100 | Kerberos 5 TGS-REP etype 23 |
| 13200 | AxCrypt 1 |
| 13300 | AxCrypt 1 in-memory SHA1 |
| 13400 | KeePass 1/2 AES |
| 13600 | WinZip |
| 18200 | Kerberos 5 AS-REP etype 23 |

Binary-file-only types (WPA `.hccapx`, TrueCrypt/VeraCrypt containers, Password Safe, etc.) are not supported — pass those directly to hashcat.
