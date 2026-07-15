<#
.SYNOPSIS
    Unpacks a Brovan dependency bundle (produced by Export-BrovanDeps.ps1) next
    to Brovan.exe / Brovan.dll on an analysis host.

.DESCRIPTION
    Expands the archive so that the following land in the Brovan directory:
        WindowsLibs\*.dll            (x64 System32 view)
        WindowsLibs\SysWOW64\*.dll   (x86 view)
        WinReg\{SYSTEM,SECURITY,SOFTWARE,HARDWARE,SAM}
        apisetmap.bin                (optional)

    Cross-platform: run under PowerShell 7 (pwsh) on Linux/macOS, or Windows
    PowerShell / pwsh on Windows. Brovan reads these paths relative to its own
    base directory (AppContext.BaseDirectory), so -Destination must be the folder
    that contains Brovan.dll (the publish/output directory).

.PARAMETER Archive
    Path to the .zip produced by Export-BrovanDeps.ps1.

.PARAMETER Destination
    Directory containing Brovan.exe / Brovan.dll. Default: current directory.

.PARAMETER Force
    Overwrite existing WindowsLibs / WinReg / apisetmap.bin in the destination.

.EXAMPLE
    pwsh ./Import-BrovanDeps.ps1 -Archive ./BrovanDeps.zip -Destination ./bin/Release/net8.0/linux-x64

.NOTES
    Pair with Export-BrovanDeps.ps1 (run on a Windows host).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$Archive,
    [string]$Destination = (Get-Location).Path,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Step  ([string]$m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Write-Ok    ([string]$m) { Write-Host "[+] $m" -ForegroundColor Green }
function Write-Warn2 ([string]$m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Write-Err2  ([string]$m) { Write-Host "[-] $m" -ForegroundColor Red }

if (-not (Test-Path $Archive)) { Write-Err2 "Archive not found: $Archive"; exit 1 }
if (-not (Test-Path $Destination)) { New-Item -ItemType Directory -Force -Path $Destination | Out-Null }
$Destination = (Resolve-Path $Destination).Path

# Warn (not fatal) if the destination doesn't look like a Brovan output dir.
$hasBrovan = (Test-Path (Join-Path $Destination 'Brovan.dll')) -or (Test-Path (Join-Path $Destination 'Brovan.exe'))
if (-not $hasBrovan) {
    Write-Warn2 "No Brovan.dll/Brovan.exe in '$Destination'. Make sure this is Brovan's output directory (AppContext.BaseDirectory)."
}

# Guard against clobbering unless -Force.
foreach ($item in @('WindowsLibs','WinReg','apisetmap.bin')) {
    $p = Join-Path $Destination $item
    if ((Test-Path $p) -and -not $Force) {
        Write-Err2 "'$p' already exists. Pass -Force to overwrite."
        exit 1
    }
}

# Expand into a temp dir first, then move the known top-level items into place so
# the manifest / stray files don't pollute the Brovan directory.
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("BrovanDepsImport_" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    Write-Step "Expanding $Archive"
    Expand-Archive -Path $Archive -DestinationPath $tmp -Force

    $moved = @()
    foreach ($item in @('WindowsLibs','WinReg','apisetmap.bin')) {
        $src = Join-Path $tmp $item
        if (Test-Path $src) {
            $dst = Join-Path $Destination $item
            if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
            Move-Item $src -Destination $dst -Force
            $moved += $item
        }
    }

    # Surface the manifest if present.
    $man = Join-Path $tmp 'BROVAN-DEPS-MANIFEST.txt'
    if (Test-Path $man) { Write-Host ''; Get-Content $man | Write-Host }

    Write-Host ''
    if ($moved) { Write-Ok "Imported: $($moved -join ', ')" } else { Write-Warn2 'Archive contained none of WindowsLibs/WinReg/apisetmap.bin.' }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# --- Verification ---------------------------------------------------------------
Write-Step 'Verifying layout'
$ok = $true

$libDir = Join-Path $Destination 'WindowsLibs'
$ntdll  = Join-Path $libDir 'ntdll.dll'
if (Test-Path $ntdll) {
    $cnt = (Get-ChildItem $libDir -Filter *.dll -File -ErrorAction SilentlyContinue).Count
    Write-Ok "WindowsLibs\ present ($cnt x64 DLLs, ntdll.dll OK)."
} else {
    Write-Err2 'WindowsLibs\ntdll.dll missing — Brovan cannot bootstrap the guest.'
    $ok = $false
}

$wow = Join-Path $libDir 'SysWOW64'
if (Test-Path (Join-Path $wow 'ntdll.dll')) {
    $cnt = (Get-ChildItem $wow -Filter *.dll -File -ErrorAction SilentlyContinue).Count
    Write-Ok "WindowsLibs\SysWOW64\ present ($cnt x86 DLLs)."
} else {
    Write-Warn2 'WindowsLibs\SysWOW64\ntdll.dll missing — x86 (WOW64) samples will not load.'
}

$regDir = Join-Path $Destination 'WinReg'
$requiredHives = @('SYSTEM','SECURITY','SOFTWARE','HARDWARE','SAM')  # Brovan VerifyRegDump set
$missingHives = @()
foreach ($h in $requiredHives) {
    $hp = Join-Path $regDir $h
    if (-not ((Test-Path $hp) -and (Get-Item $hp).Length -gt 0)) { $missingHives += $h }
}
if ($missingHives.Count -eq 0) {
    Write-Ok 'WinReg\ complete (all 5 hives present and non-empty).'
} else {
    Write-Err2 "WinReg incomplete — missing/empty: $($missingHives -join ', '). Brovan VerifyRegDump will fail."
    $ok = $false
}

if (Test-Path (Join-Path $Destination 'apisetmap.bin')) {
    Write-Ok 'apisetmap.bin present.'
} else {
    Write-Warn2 'apisetmap.bin absent — Brovan will auto-generate a custom one on first run.'
}

Write-Host ''
if ($ok) {
    Write-Ok "Dependencies ready in: $Destination"
    exit 0
} else {
    Write-Err2 'Import completed with missing critical pieces (see above).'
    exit 2
}
