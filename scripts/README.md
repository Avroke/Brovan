# Brovan dependency scripts

Brovan is a **syscall-level** emulator. At bootstrap it only maps the guest
`ntdll.dll`; every other DLL is resolved on demand. On a non-Windows host (or a
clean analysis box) it reads three things from its own base directory
(`AppContext.BaseDirectory`, i.e. next to `Brovan.dll` / `Brovan.exe`):

| Path | Purpose | Consumed by |
|------|---------|-------------|
| `WindowsLibs\*.dll` | x64 "System32" view of the Windows DLLs | `GeneralHelper.GetWindowsLibPath` (`System32` on Linux) |
| `WindowsLibs\SysWOW64\*.dll` | x86 "SysWOW64" view (needed for 32-bit samples) | `GeneralHelper.SysWOW64` |
| `WinReg\{SYSTEM,SECURITY,SOFTWARE,HARDWARE,SAM}` | real regf registry hives | `RegistryManager` / `VerifyRegDump` |
| `apisetmap.bin` *(optional)* | host ApiSet map; auto-generated on first run if absent | `BinaryEmulator.ApiSetMapPath` |

On Windows, Brovan reads the live `C:\Windows\System32` / `SysWOW64` and dumps
the hives + ApiSet map itself, so these scripts are only needed to **carry those
Windows dependencies to another machine** (e.g. a Linux analysis host).

## Export (run on Windows, elevated)

```powershell
# Curated common DLL set + all 5 hives + host ApiSet map:
.\Export-BrovanDeps.ps1 -OutputArchive C:\temp\BrovanDeps.zip -BrovanDir C:\Tools\Brovan

# Everything in System32/SysWOW64 (large), no registry:
.\Export-BrovanDeps.ps1 -IncludeAllSystem32 -SkipRegistry

# Curated set plus a couple of extra DLLs a specific sample needs:
.\Export-BrovanDeps.ps1 -ExtraDll winmm,wtsapi32
```

- **Elevation matters:** `HKLM\SECURITY` and `HKLM\SAM` can only be saved as
  Administrator. Unelevated, those two hives are skipped and Brovan's
  `VerifyRegDump` will fail on the target (the script exits with code 2 and a
  warning).
- The default DLL list covers the overwhelming majority of samples (al-khaser
  included). Use `-ExtraDll` for one-offs, or `-IncludeAllSystem32` when a
  sample resolves an unusual dependency.
- `apisetmap.bin` is optional: if `-BrovanDir` holds one from a prior run it's
  reused; otherwise the script runs Brovan once to dump the host map. If neither
  works, Brovan regenerates a custom map on first run.

## Import (run on the analysis host — Linux `pwsh` or Windows)

```powershell
pwsh ./Import-BrovanDeps.ps1 -Archive ./BrovanDeps.zip \
     -Destination ./Brovan/bin/Release/net8.0/linux-x64
```

`-Destination` must be the directory that contains `Brovan.dll` (Brovan reads
these paths relative to its own base directory). The script unpacks
`WindowsLibs\`, `WinReg\`, and `apisetmap.bin` into place and verifies the
layout: it fails loudly if `WindowsLibs\ntdll.dll` or any of the 5 hives are
missing, and warns (non-fatal) if the `SysWOW64` view or `apisetmap.bin` is
absent.

## Notes / limitations

- The hives produced by `reg save` are real `regf` hives; the wine-generated
  text `.reg` files are **not** a substitute.
- `HARDWARE` is a volatile hive — `reg save` still produces a small valid file.
- Wine's fake System32 DLLs are **not** a drop-in replacement for a real Windows
  ntdll (their internal Unix-side structures differ), so use DLLs exported from
  a genuine Windows install.
