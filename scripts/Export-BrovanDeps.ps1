<#
.SYNOPSIS
    Collects the Windows-side runtime dependencies Brovan needs to emulate PE
    binaries on a non-Windows host (or on a clean analysis box) and packs them
    into a single archive.

.DESCRIPTION
    Brovan is a syscall-level emulator: at bootstrap it only maps the guest
    'ntdll.dll', and resolves every other imported DLL on demand from a shipped
    'WindowsLibs\' directory (see GeneralHelper.GetWindowsLibPath). On Linux it
    reads:
        - WindowsLibs\            -> the x64 "System32" view (*.dll + *.nls)
        - WindowsLibs\SysWOW64\   -> the x86 "SysWOW64" view (*.dll + *.nls)
        - WinReg\{SYSTEM,SECURITY,SOFTWARE,HARDWARE,SAM}  -> real regf hives
        - apisetmap.bin           -> the host ApiSet map (optional; Brovan
                                     auto-generates one on first run if absent)

    The *.nls tables (locale.nls / sortdefault.nls / codepages) matter: kernelbase
    maps locale.nls during init, and without it kernelbase init fails and every
    sample dies before reaching its entry point.

    This script must run on a real Windows machine (ideally elevated, so the
    SECURITY and SAM hives can be saved). It stages those three pieces and
    compresses them into a .zip you can carry to the analysis host and unpack
    with Import-BrovanDeps.ps1.

    By default it copies a curated set of common user-mode runtime DLLs (enough
    for the vast majority of samples, including al-khaser). Pass
    -IncludeAllSystem32 to copy the entire System32/SysWOW64 instead (large,
    multi-GB), or -ExtraDll to add specific names to the curated set.

.PARAMETER OutputArchive
    Path to the .zip to produce. Default: .\BrovanDeps.zip

.PARAMETER IncludeAllSystem32
    Copy the ENTIRE C:\Windows\System32 and C:\Windows\SysWOW64 instead of the
    curated list. Produces a very large archive; use only when a sample needs an
    unusual DLL not in the curated set.

.PARAMETER ExtraDll
    Extra DLL names (with or without .dll) to add to the curated set, e.g.
    -ExtraDll 'wtsapi32','winmm'. Ignored when -IncludeAllSystem32 is set.

.PARAMETER SkipRegistry
    Do not dump the registry hives (useful when you only need the DLLs, or when
    running unelevated and you'll supply hives separately).

.PARAMETER BrovanDir
    Directory that contains Brovan.exe. If it holds an 'apisetmap.bin' (produced
    by a prior Brovan run on this host) that real host map is included. If not
    but Brovan.exe is present, the script runs it once against a tiny throwaway
    input to make Brovan dump the host ApiSet map, then includes it.

.PARAMETER ApiSetMap
    Explicit path to an existing apisetmap.bin to include (overrides -BrovanDir
    discovery).

.PARAMETER WorkDir
    Staging directory. Default: a fresh temp folder that is removed afterwards.

.EXAMPLE
    # Elevated PowerShell on a Windows 10/11 x64 box:
    .\Export-BrovanDeps.ps1 -OutputArchive C:\temp\BrovanDeps.zip -BrovanDir C:\Tools\Brovan

.EXAMPLE
    # Grab everything (nuclear option) and skip the registry:
    .\Export-BrovanDeps.ps1 -IncludeAllSystem32 -SkipRegistry

.NOTES
    Pair with Import-BrovanDeps.ps1 on the analysis host.
    Requires Windows. Elevate for the SECURITY and SAM hives.
#>
[CmdletBinding()]
param(
    [string]$OutputArchive = (Join-Path (Get-Location) 'BrovanDeps.zip'),
    [switch]$IncludeAllSystem32,
    [string[]]$ExtraDll = @(),
    [switch]$SkipRegistry,
    [string]$BrovanDir,
    [string]$ApiSetMap,
    [string]$WorkDir
)

$ErrorActionPreference = 'Stop'

function Write-Step   ([string]$m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok     ([string]$m) { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2  ([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2   ([string]$m) { Write-Host "[-] $m" -ForegroundColor Red }

# --- Platform + privilege checks ------------------------------------------------
if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) {
    Write-Err2 'Export-BrovanDeps.ps1 must run on Windows (it reads System32 and uses reg.exe save).'
    exit 1
}

$isAdmin = $false
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] `
                [Security.Principal.WindowsIdentity]::GetCurrent()
               ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    Write-Warn2 "Could not determine elevation state ($($_.Exception.Message)); assuming non-admin."
}

if (-not $isAdmin -and -not $SkipRegistry) {
    Write-Warn2 'Not elevated: the SECURITY and SAM hives cannot be saved. Re-run as Administrator, or pass -SkipRegistry.'
}

# --- Curated common user-mode runtime DLL set ----------------------------------
# Enough for the overwhelming majority of samples (al-khaser included). These are
# resolved on demand by the guest ntdll's loader as the target's import table is
# walked. Extend via -ExtraDll, or use -IncludeAllSystem32 for the full set.
$CuratedDlls = @(
    'ntdll','kernel32','kernelbase','KernelAppCore','win32u',
    'user32','gdi32','gdi32full','imm32','uxtheme',
    'advapi32','sechost','rpcrt4','msvcrt','msvcp_win','ucrtbase',
    'combase','ole32','oleaut32','clbcatq',
    'shell32','shlwapi','shcore','SHDocVw','windows.storage',
    'ws2_32','wsock32','mswsock','dnsapi','iphlpapi','nsi','mpr',
    'wininet','winhttp','urlmon','wldp',
    'crypt32','cryptbase','cryptsp','bcrypt','bcryptprimitives','ncrypt','ncryptsslp',
    'wintrust','msasn1','amsi',
    'comctl32','comdlg32','setupapi','cfgmgr32','devobj',
    # WUDFPlatform: al-khaser resolves WudfIs{Any,Kernel,User}DebuggerPresent from it
    # for its WUDF debugger checks; its GetProcAddress calls no-op harmlessly when absent.
    # faultrep: exists in a standard System32; shipped so a file-existence probe passes.
    # It is NOT loaded at runtime — an earlier bogus apiset override
    # (ext-ms-win-kernel32-errorhandling-l1-1-0 -> faultrep) used to drag it (and its static
    # import dbghelp.dll) into every process, which al-khaser's "loaded modules contains
    # dbghelp.dll" probe flagged. That override was removed (the contract now resolves to
    # KERNELBASE, matching real Windows), so faultrep ships on disk but stays unloaded.
    'WUDFPlatform','faultrep',
    'powrprof','umpdc','wmiclnt','psapi','version','profapi','userenv',
    'netapi32','netutils','samcli','srvcli','wkscli','logoncli',
    'secur32','sspicli','dbghelp','dbgcore','imagehlp',
    'wtsapi32','winmm','normaliz','bcp47mrm','windows.globalization',
    # Visual C++ 2015-2022 runtime (System32 when the VC++ redist is installed).
    # MSVC-compiled samples - al-khaser included - import these directly; without
    # them the loader raises STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139) binding the
    # target's imports. Warned-but-skipped if the redist isn't present on the host.
    'msvcp140','msvcp140_1','msvcp140_2','vcruntime140','vcruntime140_1',
    'concrt140','vccorlib140'
)

# --- Staging --------------------------------------------------------------------
$cleanupWork = $false
if (-not $WorkDir) {
    $WorkDir = Join-Path ([IO.Path]::GetTempPath()) ("BrovanDeps_" + [Guid]::NewGuid().ToString('N'))
    $cleanupWork = $true
}
$stage      = Join-Path $WorkDir 'stage'
$libDir     = Join-Path $stage 'WindowsLibs'
$wow64Dir   = Join-Path $libDir 'SysWOW64'
$regDir     = Join-Path $stage 'WinReg'
New-Item -ItemType Directory -Force -Path $libDir,$wow64Dir,$regDir | Out-Null

$sys32  = Join-Path $env:WINDIR 'System32'
$syswow = Join-Path $env:WINDIR 'SysWOW64'   # x86 view on x64 OS; absent on 32-bit OS
# SortDefault.nls lives under %WINDIR%\Globalization\Sorting, NOT System32; one file,
# shared by both the x64 and x86 views.
$sortNls = Join-Path $env:WINDIR 'Globalization\Sorting\SortDefault.nls'

# --- Copy DLLs ------------------------------------------------------------------
function Copy-DllSet {
    param([string]$SourceDir, [string]$DestDir, [string]$Label)
    if (-not (Test-Path $SourceDir)) { Write-Warn2 "$Label source missing: $SourceDir"; return 0 }

    if ($IncludeAllSystem32) {
        Write-Step "Copying ALL of $Label ($SourceDir) -> this can take a while and is large..."
        Copy-Item -Path (Join-Path $SourceDir '*.dll') -Destination $DestDir -Force -ErrorAction SilentlyContinue
        return (Get-ChildItem $DestDir -Filter *.dll -File -ErrorAction SilentlyContinue).Count
    }

    $names = ($CuratedDlls + $ExtraDll) |
             ForEach-Object { if ($_ -match '\.dll$') { $_ } else { "$_.dll" } } |
             Sort-Object -Unique
    $copied = 0; $missing = @()
    foreach ($n in $names) {
        $src = Join-Path $SourceDir $n
        if (Test-Path $src) {
            Copy-Item $src -Destination $DestDir -Force
            $copied++
        } else {
            $missing += $n
        }
    }
    if ($missing.Count) { Write-Warn2 "${Label}: $($missing.Count) curated DLL(s) not present on this host: $($missing -join ', ')" }
    return $copied
}

# NLS (National Language Support) tables live in System32 as *.nls, NOT *.dll, so
# the DLL copy skips them. kernelbase.dll's init calls NtInitializeNlsFiles and
# maps locale.nls; without it kernelbase init FAILS (STATUS_DLL_INIT_FAILED) and
# every sample dies before main. Always ship them (small: a few MB total).
#
# SortDefault.nls is also required: kernel32!SortGetHandle loads it lazily on the first
# case-insensitive comparison (CompareStringW, StrCmpNIW, lstrcmpi ...). Without it the
# sort registry never populates, every collation returns a constant error, and
# al-khaser's DLL-injection check (which case-insensitively compares each loaded module's
# path against the System32 prefix) flags every legitimate System32 module as "injected
# library" -- a fully-covered fix (see F3 / commit b205488) that depends on the file being
# shipped. Unlike locale.nls / codepages it does NOT live in System32: it sits at
# %WINDIR%\Globalization\Sorting\SortDefault.nls (one architecture-independent file, shared
# by the x64 and x86 views), so it is copied separately from $SortSource. Brovan's
# WindowsLibs resolver maps any C:\Windows\Globalization\... open by leaf into the flat
# WindowsLibs\ set (see commit 2f6e5ae), so the file only needs to land next to the other
# *.nls, not under a Globalization\Sorting\ subdirectory.
function Copy-NlsSet {
    param([string]$SourceDir, [string]$DestDir, [string]$Label, [string]$SortSource)
    if (-not (Test-Path $SourceDir)) { return 0 }
    Copy-Item -Path (Join-Path $SourceDir '*.nls') -Destination $DestDir -Force -ErrorAction SilentlyContinue

    if ($SortSource -and (Test-Path $SortSource)) {
        Copy-Item -Path $SortSource -Destination (Join-Path $DestDir 'SortDefault.nls') -Force -ErrorAction SilentlyContinue
    }

    $cnt = (Get-ChildItem $DestDir -Filter *.nls -File -ErrorAction SilentlyContinue).Count
    if (-not (Test-Path (Join-Path $DestDir 'locale.nls'))) {
        Write-Warn2 "${Label}: locale.nls not found - kernelbase init will fail on the target."
    }
    if (-not (Test-Path (Join-Path $DestDir 'SortDefault.nls'))) {
        Write-Warn2 "${Label}: SortDefault.nls not found (looked for '$SortSource') - case-insensitive comparison will fail; al-khaser will flag every System32 module as injected."
    }
    return $cnt
}

Write-Step "Staging x64 DLLs (System32 view -> WindowsLibs\)"
$n64 = Copy-DllSet -SourceDir $sys32 -DestDir $libDir -Label 'System32 (x64)'
$nls64 = Copy-NlsSet -SourceDir $sys32 -DestDir $libDir -Label 'System32 (x64)' -SortSource $sortNls
Write-Ok  "x64: $n64 DLL(s) + $nls64 NLS file(s) staged."

Write-Step "Staging x86 DLLs (SysWOW64 view -> WindowsLibs\SysWOW64\)"
$n86 = Copy-DllSet -SourceDir $syswow -DestDir $wow64Dir -Label 'SysWOW64 (x86)'
$nls86 = Copy-NlsSet -SourceDir $syswow -DestDir $wow64Dir -Label 'SysWOW64 (x86)' -SortSource $sortNls
Write-Ok  "x86: $n86 DLL(s) + $nls86 NLS file(s) staged."

# --- Registry hives -------------------------------------------------------------
$hivesSaved = @()
if (-not $SkipRegistry) {
    Write-Step 'Dumping registry hives (reg save)'
    $hiveMap = [ordered]@{
        'SYSTEM'   = 'HKLM\SYSTEM'
        'SOFTWARE' = 'HKLM\SOFTWARE'
        'HARDWARE' = 'HKLM\HARDWARE'
        'SECURITY' = 'HKLM\SECURITY'
        'SAM'      = 'HKLM\SAM'
    }
    foreach ($name in $hiveMap.Keys) {
        $dest = Join-Path $regDir $name
        $key  = $hiveMap[$name]
        # HARDWARE is a volatile hive; reg save produces a small but valid file.
        $p = Start-Process -FilePath 'reg.exe' -ArgumentList @('save', $key, "`"$dest`"", '/y') `
                           -NoNewWindow -Wait -PassThru -RedirectStandardOutput ([IO.Path]::GetTempFileName()) `
                           -RedirectStandardError  ([IO.Path]::GetTempFileName())
        if ($p.ExitCode -eq 0 -and (Test-Path $dest) -and (Get-Item $dest).Length -gt 0) {
            $hivesSaved += $name
            Write-Ok "Saved hive $name"
        } else {
            Write-Warn2 "Failed to save hive $name ($key) - need elevation for SECURITY/SAM."
        }
    }
} else {
    Write-Warn2 'Skipping registry dump (-SkipRegistry).'
}

# --- ApiSet map -----------------------------------------------------------------
$apiSetIncluded = $false
$apiSetDest = Join-Path $stage 'apisetmap.bin'

function Include-ApiSetMap {
    param([string]$Path)
    if ($Path -and (Test-Path $Path) -and (Get-Item $Path).Length -gt 0) {
        Copy-Item $Path -Destination $apiSetDest -Force
        return $true
    }
    return $false
}

if ($ApiSetMap) {
    if (Include-ApiSetMap $ApiSetMap) {
        $apiSetIncluded = $true; Write-Ok "Included apisetmap.bin from -ApiSetMap."
    } else {
        Write-Warn2 "-ApiSetMap path invalid or empty: $ApiSetMap"
    }
}

if (-not $apiSetIncluded -and $BrovanDir) {
    $existing = Join-Path $BrovanDir 'apisetmap.bin'
    if (Include-ApiSetMap $existing) {
        $apiSetIncluded = $true
        Write-Ok "Included existing apisetmap.bin from $BrovanDir."
    } else {
        $exe = Join-Path $BrovanDir 'Brovan.exe'
        if (Test-Path $exe) {
            Write-Step "No apisetmap.bin yet; running Brovan once to make it dump the host map..."
            try {
                # Brovan dumps the host ApiSet map from its own PEB at startup when
                # apisetmap.bin is missing; feed a bogus path + immediate exit.
                $tmpIn = [IO.Path]::GetTempFileName()
                Start-Process -FilePath $exe -ArgumentList @('-c', 'exit', "`"$tmpIn`"") `
                              -WorkingDirectory $BrovanDir -NoNewWindow -Wait `
                              -RedirectStandardOutput ([IO.Path]::GetTempFileName()) `
                              -RedirectStandardError  ([IO.Path]::GetTempFileName()) | Out-Null
                Remove-Item $tmpIn -ErrorAction SilentlyContinue
                if (Include-ApiSetMap $existing) { $apiSetIncluded = $true; Write-Ok 'Brovan produced apisetmap.bin; included.' }
            } catch {
                Write-Warn2 "Could not auto-run Brovan to dump apisetmap.bin: $($_.Exception.Message)"
            }
        }
    }
}

if (-not $apiSetIncluded) {
    Write-Warn2 'No apisetmap.bin included. Brovan will auto-generate a custom one on first run (fallback path).'
}

# --- Manifest -------------------------------------------------------------------
$os = $null
try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
if ($os) {
    $srcDesc = '{0} (build {1}, {2})' -f $os.Caption, $os.BuildNumber, $os.OSArchitecture
} else {
    $srcDesc = [Environment]::OSVersion.VersionString
}
$manifest = @(
    'Brovan dependency bundle'
    ('Created : {0:yyyy-MM-dd HH:mm:ss} UTC' -f (Get-Date).ToUniversalTime())
    ('Source  : {0}' -f $srcDesc)
    ('Mode    : {0}' -f ($(if ($IncludeAllSystem32) { 'ALL System32/SysWOW64' } else { 'curated DLL set' })))
    ('DLLs    : x64={0}  x86={1}' -f $n64, $n86)
    ('NLS     : x64={0}  x86={1}' -f $nls64, $nls86)
    ('Hives   : {0}' -f ($(if ($hivesSaved) { $hivesSaved -join ', ' } else { '(none)' })))
    ('ApiSet  : {0}' -f ($(if ($apiSetIncluded) { 'apisetmap.bin included' } else { 'not included (Brovan will generate)' })))
    ''
    'Layout expected next to Brovan.exe/Brovan.dll:'
    '  WindowsLibs\*.dll             (x64 System32 view)'
    '  WindowsLibs\*.nls             (locale/codepage tables; kernelbase init)'
    '  WindowsLibs\SysWOW64\*.dll    (x86 view)'
    '  WinReg\{SYSTEM,SECURITY,SOFTWARE,HARDWARE,SAM}'
    '  apisetmap.bin                 (optional)'
    ''
    'Import with: .\Import-BrovanDeps.ps1 -Archive <this.zip> -Destination <BrovanDir>'
) -join [Environment]::NewLine
$manifest | Set-Content -Path (Join-Path $stage 'BROVAN-DEPS-MANIFEST.txt') -Encoding UTF8

# --- Compress -------------------------------------------------------------------
Write-Step "Compressing -> $OutputArchive"
$outDir = Split-Path -Parent $OutputArchive
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
if (Test-Path $OutputArchive) { Remove-Item $OutputArchive -Force }
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $OutputArchive -CompressionLevel Optimal

$sizeMb = [math]::Round((Get-Item $OutputArchive).Length / 1MB, 1)
Write-Ok "Wrote $OutputArchive ($sizeMb MB)."
Write-Host ''
Write-Host $manifest

# --- Cleanup --------------------------------------------------------------------
if ($cleanupWork) {
    Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $hivesSaved -and -not $SkipRegistry) {
    Write-Warn2 'No hives were saved: Brovan VerifyRegDump will fail on the target. Re-run elevated.'
    exit 2
}
exit 0
