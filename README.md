# utils

Personal offensive utility scripts for Kerberos-related attacks. Provided as-is with no guarantees — review before use in any environment you care about.

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
