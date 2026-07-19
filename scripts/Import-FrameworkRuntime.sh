#!/usr/bin/env bash
#
# Import-FrameworkRuntime.sh - stage a real .NET Framework 4.x x64 runtime into a
# Brovan output directory so a MANAGED .NET Framework PE (net4x, x64) can bootstrap
# the real CLR (mscoree -> mscoreei -> clr -> clrjit -> mscorlib -> Main), exactly
# as Brovan already does for self-contained .NET Core apps (coreclr).
#
# Where the pieces land (relative to Brovan's base directory = the folder with
# Brovan.dll):
#   WindowsLibs/mscoree.dll                                  <- the System32 CLR shim
#   VirtualFS/C/Windows/Microsoft.NET/Framework64/v4.0.30319/*.dll   <- the runtime
#
# The mscoree.dll SHIM: on modern Windows mscoree.dll (System32) is a thin stub that
# forwards to mscoreei.dll (the real shim engine). The .NET Framework redistributable
# ships mscoreei.dll but NOT mscoree.dll (mscoree.dll is a Windows OS component). Since
# mscoreei.dll exports the full shim surface the managed PE imports (_CorExeMain,
# _CorExeMain2, _CorDllMain, CorExitProcess, CLRCreateInstance, ...), we stage it AS
# mscoree.dll. The runtime-discovery registry keys (.NETFramework\InstallRoot,
# NDP\v4\Full) are seeded in code (WinSyscallsHelper.cs), so no hive edit is needed.
#
# Usage:
#   ./Import-FrameworkRuntime.sh -s <source-dir> -d ./bin/Release/net8.0 [--force]
#
#   -s, --source <dir>   Directory holding the extracted Framework DLLs. Either a flat
#                        dir (clr.dll, clrjit.dll, mscoreei.dll, mscorlib.dll, ...) or a
#                        WinSxS tree (amd64_netfx4-*_4.0.15744.*\*.dll), e.g. the payload
#                        of the .NET 4.8 offline installer (ndp48-*.exe) expanded with
#                        7z/cabextract. amd64 (x64) variants are selected.
#   -d, --destination <dir>  Brovan output dir containing Brovan.dll (default: cwd).
#   -f, --force          Overwrite an existing staged runtime.
#   -h, --help           Show this help.
#
# Exit codes: 0 = staged, 1 = usage error, 2 = missing critical DLLs.

set -euo pipefail

if [ -t 1 ]; then
    C_CYAN=$'\033[36m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_RED=$'\033[31m'; C_RST=$'\033[0m'
else
    C_CYAN=''; C_GREEN=''; C_YELLOW=''; C_RED=''; C_RST=''
fi
info(){ echo "${C_CYAN}[*]${C_RST} $*"; }
ok(){ echo "${C_GREEN}[+]${C_RST} $*"; }
warn(){ echo "${C_YELLOW}[!]${C_RST} $*"; }
err(){ echo "${C_RED}[-]${C_RST} $*" >&2; }

SOURCE=""; DEST="$(pwd)"; FORCE=0
while [ $# -gt 0 ]; do
    case "$1" in
        -s|--source) SOURCE="${2:-}"; shift 2;;
        -d|--destination) DEST="${2:-}"; shift 2;;
        -f|--force) FORCE=1; shift;;
        -h|--help) sed -n '2,40p' "$0"; exit 0;;
        *) err "Unknown option: $1"; exit 1;;
    esac
done

[ -n "$SOURCE" ] && [ -d "$SOURCE" ] || { err "Source directory required (-s). Not found: '$SOURCE'"; exit 1; }
[ -f "$DEST/Brovan.dll" ] || warn "No Brovan.dll in destination '$DEST' (staging anyway)."

FWDIR="$DEST/VirtualFS/C/Windows/Microsoft.NET/Framework64/v4.0.30319"
WINLIBS="$DEST/WindowsLibs"
mkdir -p "$FWDIR" "$WINLIBS"

# Pick the amd64/x64 variant of <name> from the source tree (prefers the highest
# 4.0.15744.* build if several are present).
pick(){
    find "$SOURCE" -type f -iname "$1" 2>/dev/null \
        | grep -iE 'amd64|x64|64' \
        | sort -t. -k4 -rn | head -1
    # fall back to any match if no amd64-tagged path
}
pick_any(){ find "$SOURCE" -type f -iname "$1" 2>/dev/null | head -1; }

stage(){ # <name> <required 0/1>
    local name="$1" req="$2" src dst="$FWDIR/$1"
    src="$(pick "$name")"; [ -n "$src" ] || src="$(pick_any "$name")"
    if [ -z "$src" ]; then
        [ "$req" = 1 ] && { err "Missing required runtime DLL: $name"; return 2; }
        warn "optional DLL not found (skipped): $name"; return 0
    fi
    if [ -e "$dst" ] && [ "$FORCE" != 1 ]; then warn "exists (use --force): $name"; else cp -f "$src" "$dst"; fi
    ok "Framework64\\v4.0.30319\\$name  <-  $(basename "$(dirname "$src")")"
}

RC=0
for d in clr.dll clrjit.dll mscoreei.dll mscorlib.dll; do stage "$d" 1 || RC=2; done
for d in mscordacwks.dll mscordbi.dll mscorrc.dll mscorsecimpl.dll; do stage "$d" 0 || true; done
[ "$RC" = 2 ] && { err "Critical runtime DLLs missing; aborting."; exit 2; }

# The mscoree.dll System32 shim bridge (= mscoreei engine).
MSCOREEI="$(pick mscoreei.dll)"; [ -n "$MSCOREEI" ] || MSCOREEI="$(pick_any mscoreei.dll)"
if [ -e "$WINLIBS/mscoree.dll" ] && [ "$FORCE" != 1 ]; then
    warn "WindowsLibs/mscoree.dll exists (use --force)"
else
    cp -f "$MSCOREEI" "$WINLIBS/mscoree.dll"
fi
ok "WindowsLibs\\mscoree.dll  <-  mscoreei.dll (shim bridge)"

info "Runtime-discovery registry keys (.NETFramework\\InstallRoot, NDP\\v4\\Full) are"
info "seeded in code (WinSyscallsHelper.cs); no hive edit required."
ok "Framework runtime staged. Run a net4x x64 PE with: dotnet Brovan.dll <app.exe> then 'start'."
exit 0
