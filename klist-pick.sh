#!/usr/bin/env bash
# klist-pick.sh - scan for .ccache files, preview with klist, and select one as KRB5CCNAME
#
# Requirements:
#   klist    - Kerberos ticket list (apt: krb5-user)
#   python3  - expiry timestamp parsing
#
# Usage:
#   source klist-pick.sh          # sets KRB5CCNAME in the current shell
#
# Note:
#   This script must be sourced for the export to take effect in the current shell.

# Colours
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
BOLD='\033[1m'
RESET='\033[0m'

# Make unmatched globs expand to empty rather than error (bash + zsh)
setopt null_glob 2>/dev/null || true
shopt -s nullglob 2>/dev/null || true

while true; do
    # Collect .ccache files in the current directory
    files=(*.ccache)

    if [ ${#files[@]} -eq 0 ]; then
        printf "${RED}[!] No .ccache files found in %s${RESET}\n" "$(pwd)" >&2
        break
    fi

    # Display menu
    echo "" >&2
    printf "${BOLD}  .ccache files in %s:${RESET}\n" "$(pwd)" >&2
    echo "" >&2

    # Show currently active ccache if set
    if [ -n "$KRB5CCNAME" ]; then
        printf "${GREEN}  Active: %s${RESET}\n" "$KRB5CCNAME" >&2
        echo "" >&2
    fi

    i=1
    for f in "${files[@]}"; do
        # Extract default principal for display
        principal=$(KRB5CCNAME="FILE:$(cd "$(dirname "$f")" && pwd)/$(basename "$f")" klist 2>/dev/null | awk '/^Default principal:/ { print $3; exit }')
        if [ -n "$principal" ]; then
            printf "  ${YELLOW}[%d]${RESET} %-40s ${BLUE}%s${RESET}\n" "$i" "$f" "$principal" >&2
        else
            printf "  ${YELLOW}[%d]${RESET} %s\n" "$i" "$f" >&2
        fi
        i=$((i + 1))
    done
    echo "" >&2
    printf "  ${YELLOW}[q]${RESET} Quit\n" >&2
    echo "" >&2
    printf "  Select a file: " >&2
    if ! IFS= read -r choice; then
        printf "\n${YELLOW}[*] Aborted.${RESET}\n" >&2
        break
    fi

    # Quit
    if [ "$choice" = "q" ] || [ "$choice" = "Q" ]; then
        printf "${YELLOW}[*] Aborted.${RESET}\n" >&2
        break
    fi

    # Validate numeric input
    case "$choice" in
        ''|*[!0-9]*)
            printf "${RED}[!] Invalid selection.${RESET}\n" >&2
            continue
            ;;
    esac

    if [ "$choice" -lt 1 ] || [ "$choice" -gt ${#files[@]} ]; then
        printf "${RED}[!] Invalid selection.${RESET}\n" >&2
        continue
    fi

    # Get selected file — walk the array to avoid bash/zsh index differences
    i=1
    selected=""
    for f in "${files[@]}"; do
        if [ "$i" -eq "$choice" ]; then
            selected="$f"
            break
        fi
        i=$((i + 1))
    done
    abs_path="$(cd "$(dirname "$selected")" && pwd)/$(basename "$selected")"

    # Run klist against the selected file
    echo "" >&2
    printf "${BOLD}  klist: %s${RESET}\n" "$abs_path" >&2
    printf "${BLUE}  ──────────────────────────────────────────${RESET}\n" >&2
    klist_out=$(KRB5CCNAME="FILE:${abs_path}" klist 2>&1)
    while IFS= read -r line; do
        printf "${BLUE}  %s${RESET}\n" "$line" >&2
    done <<EOF
$klist_out
EOF
    printf "${BLUE}  ──────────────────────────────────────────${RESET}\n" >&2

    # Check expiry by parsing the earliest expiry timestamp from ticket lines.
    # klist format: MM/DD/YYYY HH:MM:SS  MM/DD/YYYY HH:MM:SS  service
    # The expiry is the second date/time pair on each ticket line.
    expired=0
    no_creds=0
    if echo "$klist_out" | grep -q "No credentials cache\|Credentials cache.*not found"; then
        no_creds=1
    else
        while IFS= read -r line; do
            # Match lines with two MM/DD/YYYY HH:MM:SS timestamps
            if echo "$line" | grep -qE '^[[:space:]]*[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}'; then
                # Extract the expiry field (second timestamp: fields 3 and 4)
                exp_date=$(echo "$line" | awk '{print $3, $4}')
                # Use python3 to parse and compare — pass via argv to avoid injection
                is_expired=$(python3 - "$exp_date" <<'PY'
from datetime import datetime
import sys
try:
    exp = datetime.strptime(sys.argv[1], '%m/%d/%Y %H:%M:%S')
    print('1' if exp < datetime.now() else '0')
except Exception:
    print('0')
PY
)
                if [ "$is_expired" = "1" ]; then
                    expired=1
                    break
                fi
            fi
        done <<EOF
$(echo "$klist_out")
EOF
    fi

    if [ "$no_creds" -eq 1 ]; then
        echo "" >&2
        printf "${RED}  [!] WARNING: no credentials cache found${RESET}\n" >&2
    elif [ "$expired" -eq 1 ]; then
        echo "" >&2
        printf "${RED}  [!] WARNING: ticket is expired${RESET}\n" >&2
    fi
    echo "" >&2

    # Prompt: set or go back
    printf "  ${YELLOW}[s]${RESET} Set KRB5CCNAME  ${YELLOW}[b]${RESET} Back to menu  ${YELLOW}[q]${RESET} Quit: " >&2
    if ! IFS= read -r action; then
        printf "\n${YELLOW}[*] Aborted.${RESET}\n" >&2
        break
    fi

    case "$action" in
        s|S)
            export KRB5CCNAME="FILE:${abs_path}"
            printf "${GREEN}[+] KRB5CCNAME set to: FILE:%s${RESET}\n" "$abs_path" >&2
            break
            ;;
        b|B)
            continue
            ;;
        q|Q)
            printf "${YELLOW}[*] Aborted.${RESET}\n" >&2
            break
            ;;
        *)
            printf "${RED}[!] Invalid input, returning to menu.${RESET}\n" >&2
            continue
            ;;
    esac
done
