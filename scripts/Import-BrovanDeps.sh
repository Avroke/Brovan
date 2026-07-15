#!/usr/bin/env bash
#
# Import-BrovanDeps.sh — unpack a Brovan dependency bundle next to
# Brovan.dll / Brovan.exe on a Linux/macOS analysis host, WITHOUT needing
# PowerShell 7. POSIX-friendly bash mirror of Import-BrovanDeps.ps1.
#
# The bundle (produced by Export-BrovanDeps.ps1 on a Windows box) is a .zip
# containing, relative to Brovan's base directory (AppContext.BaseDirectory):
#     WindowsLibs/*.dll            (x64 System32 view)
#     WindowsLibs/SysWOW64/*.dll   (x86 view)
#     WinReg/{SYSTEM,SECURITY,SOFTWARE,HARDWARE,SAM}
#     apisetmap.bin                (optional)
#
# Usage:
#   ./Import-BrovanDeps.sh -a BrovanDeps.zip -d ./bin/Release/net8.0/linux-x64 [--force]
#
# Options:
#   -a, --archive <path>       Path to the .zip bundle (required).
#   -d, --destination <dir>    Directory containing Brovan.dll (default: cwd).
#   -f, --force                Overwrite existing WindowsLibs/WinReg/apisetmap.bin.
#   -h, --help                 Show this help.
#
# Exit codes: 0 = ready, 1 = usage/clobber error, 2 = missing critical pieces.

set -euo pipefail

# --- pretty printers (color only when stdout is a tty) --------------------------
if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_RST=$'\033[0m'
else
    C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_RST=''
fi
step() { printf '%s[*] %s%s\n' "$C_CYAN"   "$1" "$C_RST"; }
ok()   { printf '%s[+] %s%s\n' "$C_GREEN"  "$1" "$C_RST"; }
warn() { printf '%s[!] %s%s\n' "$C_YELLOW" "$1" "$C_RST"; }
err()  { printf '%s[-] %s%s\n' "$C_RED"    "$1" "$C_RST" 1>&2; }

# Print the leading comment block (skip the shebang, stop at the first code line).
usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' "$0"; }

# --- arg parsing ----------------------------------------------------------------
ARCHIVE=""
DEST="$(pwd)"
FORCE=0

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--archive)     ARCHIVE="${2:-}"; shift 2 ;;
        -d|--destination) DEST="${2:-}";    shift 2 ;;
        -f|--force)       FORCE=1;          shift ;;
        -h|--help)        usage; exit 0 ;;
        *) err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

if [ -z "$ARCHIVE" ]; then err "Missing required -a/--archive."; usage; exit 1; fi
if [ ! -f "$ARCHIVE" ]; then err "Archive not found: $ARCHIVE"; exit 1; fi

mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"

# Warn (non-fatal) if the destination doesn't look like a Brovan output dir.
if [ ! -f "$DEST/Brovan.dll" ] && [ ! -f "$DEST/Brovan.exe" ]; then
    warn "No Brovan.dll/Brovan.exe in '$DEST'. Make sure this is Brovan's output directory (AppContext.BaseDirectory)."
fi

# Guard against clobbering unless --force.
for item in WindowsLibs WinReg apisetmap.bin; do
    if [ -e "$DEST/$item" ] && [ "$FORCE" -ne 1 ]; then
        err "'$DEST/$item' already exists. Pass --force to overwrite."
        exit 1
    fi
done

# --- pick an extractor (bundle is a .zip from Compress-Archive) ------------------
extract_zip() {
    local zip="$1" out="$2"
    if command -v unzip >/dev/null 2>&1; then
        unzip -q -o "$zip" -d "$out"
    elif command -v 7z >/dev/null 2>&1; then
        7z x -y -o"$out" "$zip" >/dev/null
    elif command -v 7za >/dev/null 2>&1; then
        7za x -y -o"$out" "$zip" >/dev/null
    elif command -v bsdtar >/dev/null 2>&1; then
        bsdtar -x -f "$zip" -C "$out"
    else
        err "No zip extractor found (need one of: unzip, 7z, 7za, bsdtar)."
        return 3
    fi
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/BrovanDepsImport.XXXXXX")"
# shellcheck disable=SC2317  # invoked indirectly via trap
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

step "Expanding $ARCHIVE"
if ! extract_zip "$ARCHIVE" "$TMP"; then
    exit 1
fi

# --- move the known top-level items into place ----------------------------------
moved=""
for item in WindowsLibs WinReg apisetmap.bin; do
    if [ -e "$TMP/$item" ]; then
        rm -rf "${DEST:?}/$item"
        mv "$TMP/$item" "$DEST/$item"
        moved="$moved $item"
    fi
done

# Surface the manifest if present.
if [ -f "$TMP/BROVAN-DEPS-MANIFEST.txt" ]; then
    echo
    cat "$TMP/BROVAN-DEPS-MANIFEST.txt"
fi

echo
if [ -n "$moved" ]; then
    ok "Imported:$moved"
else
    warn "Archive contained none of WindowsLibs/WinReg/apisetmap.bin."
fi

# --- verification ---------------------------------------------------------------
step "Verifying layout"
status_ok=1

lib_dir="$DEST/WindowsLibs"
if [ -f "$lib_dir/ntdll.dll" ]; then
    cnt=$(find "$lib_dir" -maxdepth 1 -type f -iname '*.dll' 2>/dev/null | wc -l | tr -d ' ')
    ok "WindowsLibs/ present ($cnt x64 DLLs, ntdll.dll OK)."
else
    err "WindowsLibs/ntdll.dll missing — Brovan cannot bootstrap the guest."
    status_ok=0
fi

wow_dir="$lib_dir/SysWOW64"
if [ -f "$wow_dir/ntdll.dll" ]; then
    cnt=$(find "$wow_dir" -maxdepth 1 -type f -iname '*.dll' 2>/dev/null | wc -l | tr -d ' ')
    ok "WindowsLibs/SysWOW64/ present ($cnt x86 DLLs)."
else
    warn "WindowsLibs/SysWOW64/ntdll.dll missing — x86 (WOW64) samples will not load."
fi

reg_dir="$DEST/WinReg"
missing_hives=""
for h in SYSTEM SECURITY SOFTWARE HARDWARE SAM; do   # Brovan VerifyRegDump set
    if [ ! -s "$reg_dir/$h" ]; then
        missing_hives="$missing_hives $h"
    fi
done
if [ -z "$missing_hives" ]; then
    ok "WinReg/ complete (all 5 hives present and non-empty)."
else
    err "WinReg incomplete — missing/empty:$missing_hives. Brovan VerifyRegDump will fail."
    status_ok=0
fi

if [ -s "$DEST/apisetmap.bin" ]; then
    ok "apisetmap.bin present."
else
    warn "apisetmap.bin absent — Brovan will auto-generate a custom one on first run."
fi

echo
if [ "$status_ok" -eq 1 ]; then
    ok "Dependencies ready in: $DEST"
    exit 0
else
    err "Import completed with missing critical pieces (see above)."
    exit 2
fi
