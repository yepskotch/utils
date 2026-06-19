#!/usr/bin/env python3
"""klist-pick - scan for .ccache files, preview with klist, and select one as KRB5CCNAME.

Requirements:
    klist  - Kerberos ticket list (apt: krb5-user)

Usage:
    klist-pick

When a cache is selected, the command prints the export line you need to run:

    export KRB5CCNAME="FILE:/abs/path/to/file.ccache"

Copy and paste that line into your shell to activate the cache.  A subprocess
cannot modify its parent shell's environment, so this step is always manual.
"""

import glob
import os
import re
import subprocess
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI colours
# ---------------------------------------------------------------------------
RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
BLUE   = '\033[0;34m'
YELLOW = '\033[0;33m'
BOLD   = '\033[1m'
RESET  = '\033[0m'


def err(msg: str = "") -> None:
    """Write a line to stderr (menus, prompts, status messages)."""
    print(msg, file=sys.stderr)


def get_principal(abs_path: str) -> str:
    """Return the default principal from a ccache file, or empty string."""
    env = {**os.environ, "KRB5CCNAME": f"FILE:{abs_path}"}
    result = subprocess.run(
        ["klist"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    for line in result.stdout.splitlines():
        if line.startswith("Default principal:"):
            parts = line.split()
            if len(parts) >= 3:
                return parts[2]
    return ""


def run_klist(abs_path: str) -> str:
    """Return full klist output for a ccache file."""
    env = {**os.environ, "KRB5CCNAME": f"FILE:{abs_path}"}
    result = subprocess.run(
        ["klist"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return result.stdout


def check_expiry(klist_out: str):
    """
    Returns ("no_creds", None) | ("expired", None) | ("ok", None).
    Parses ticket lines with two MM/DD/YYYY HH:MM:SS timestamps;
    the second is the expiry.
    """
    if re.search(r'No credentials cache|Credentials cache.*not found', klist_out):
        return "no_creds"

    # Match lines: MM/DD/YYYY HH:MM:SS  MM/DD/YYYY HH:MM:SS  <service>
    timestamp_re = re.compile(
        r'^\s*(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+'
        r'(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})'
    )
    for line in klist_out.splitlines():
        m = timestamp_re.match(line)
        if m:
            exp_str = m.group(2).strip()
            try:
                exp = datetime.strptime(exp_str, '%m/%d/%Y %H:%M:%S')
                if exp < datetime.now():
                    return "expired"
            except ValueError:
                pass

    return "ok"


def main() -> None:
    while True:
        # Collect .ccache files in the current directory
        files = sorted(glob.glob("*.ccache"))

        if not files:
            err(f"{RED}[!] No .ccache files found in {os.getcwd()}{RESET}")
            sys.exit(1)

        # Display menu
        err("")
        err(f"{BOLD}  .ccache files in {os.getcwd()}:{RESET}")
        err("")

        # Show currently active ccache if set
        active = os.environ.get("KRB5CCNAME", "")
        if active:
            err(f"{GREEN}  Active: {active}{RESET}")
            err("")

        for idx, f in enumerate(files, start=1):
            abs_path = os.path.abspath(f)
            principal = get_principal(abs_path)
            if principal:
                err(f"  {YELLOW}[{idx}]{RESET} {f:<40} {BLUE}{principal}{RESET}")
            else:
                err(f"  {YELLOW}[{idx}]{RESET} {f}")

        err("")
        err(f"  {YELLOW}[q]{RESET} Quit")
        err("")

        try:
            choice_raw = input("  Select a file: ").strip()
        except (EOFError, KeyboardInterrupt):
            err(f"\n{YELLOW}[*] Aborted.{RESET}")
            sys.exit(0)

        if choice_raw.lower() == "q":
            err(f"{YELLOW}[*] Aborted.{RESET}")
            sys.exit(0)

        if not choice_raw.isdigit():
            err(f"{RED}[!] Invalid selection.{RESET}")
            continue

        choice = int(choice_raw)
        if choice < 1 or choice > len(files):
            err(f"{RED}[!] Invalid selection.{RESET}")
            continue

        selected = files[choice - 1]
        abs_path = os.path.abspath(selected)

        # Preview with klist
        err("")
        err(f"{BOLD}  klist: {abs_path}{RESET}")
        err(f"{BLUE}  ──────────────────────────────────────────{RESET}")
        klist_out = run_klist(abs_path)
        for line in klist_out.splitlines():
            err(f"{BLUE}  {line}{RESET}")
        err(f"{BLUE}  ──────────────────────────────────────────{RESET}")

        # Expiry / validity check
        status = check_expiry(klist_out)
        if status == "no_creds":
            err("")
            err(f"{RED}  [!] WARNING: no credentials cache found{RESET}")
        elif status == "expired":
            err("")
            err(f"{RED}  [!] WARNING: ticket is expired{RESET}")

        err("")

        # Prompt: print / back / quit
        try:
            action = input(
                f"  {YELLOW}[p]{RESET} Print export command  "
                f"{YELLOW}[b]{RESET} Back to menu  "
                f"{YELLOW}[q]{RESET} Quit: "
            ).strip().lower()
        except (EOFError, KeyboardInterrupt):
            err(f"\n{YELLOW}[*] Aborted.{RESET}")
            sys.exit(0)

        if action == "p":
            export_cmd = f'export KRB5CCNAME="FILE:{abs_path}"'
            err("")
            err(f"{GREEN}[+] Run the following command in your shell to activate this cache:{RESET}")
            err("")
            err(f"    {BOLD}{export_cmd}{RESET}")
            err("")
            sys.exit(0)
        elif action == "b":
            continue
        elif action == "q":
            err(f"{YELLOW}[*] Aborted.{RESET}")
            sys.exit(0)
        else:
            err(f"{RED}[!] Invalid input, returning to menu.{RESET}")
            continue


if __name__ == "__main__":
    main()
