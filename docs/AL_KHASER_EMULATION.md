# al-khaser emulation — corrections log

Running the [al-khaser](https://github.com/ayoubfaouzi/al-khaser) anti-VM /
anti-debug / anti-analysis suite through Brovan on a **non-Windows host** (Linux
x86-64) surfaced a chain of loader, filesystem, syscall and threading gaps.
This file records every correction that has landed, and every frontier that has
been diagnosed but not yet fixed, so the work can be picked up without
re-deriving the analysis.

Scope: **al-khaser x64**. al-khaser x86 does not run at all — Brovan implements
very few x86 syscalls and no WOW64 (see Frontier F5).

## Progression

Each landed fix unblocked the next layer. Instruction counts are for
`al-khaser_x64.exe` run to its terminus via `start` (see *Reproduction*).

| Stage | Instructions | Terminus reached |
|-------|-------------:|------------------|
| Session start | 37 369 | guest ntdll failed to load |
| Unicorn 2.1.4 (host env only) | 1 250 973 | import bind |
| NLS tables shipped | 4 995 027 | `STATUS_DLL_INIT_FAILED` cleared |
| Real VC++ runtime shipped | 5 258 589 | `0xC0000142` cleared |
| **`e70c2b5`** apiset heap-obsolete | 13 513 868 | `0xC0000139` cleared; entry point + CRT run |
| **`b15fab0`** seed VFS system images | 22 850 816 | `std::filesystem::equivalent` throw cleared |
| **`4b9540f`** NtReadVirtualMemory by-value | 22.8 M+ (module enum completes) | injected-library AV cleared |
| **`ed5b1ab`** guest image path | 22.8 M+ | `log.txt` create + own-image / `equivalent` host-path leak cleared |
| **`2f6e5ae`** QueryDosDevice / PIFN / NLS path | 22.8 M+ | anti-injection prerequisites fixed (FP residual = NLS collation, F3) |
| **`bc151f0`** IRETQ probe memo | 24.1 M (throughput; terminus unchanged) | ~11 % of CPU-bound run time reclaimed on the per-instruction hot path |
| **`b205488`** NLS sort-table open (leaf-extraction) | 24.1 M+ | injected-library **false positive fixed** (case-insensitive collation now correct) + NLS re-open storm ended |

al-khaser now loads fully, runs its detection suite, walks the PEB loader lists,
enumerates its modules, and prints its verdicts. The last four fixes do not move
the instruction terminus — they close specific behavioural/stealth gaps
(dropped-file capture, injected-DLL prerequisites, the injected-DLL false
positive itself) or reclaim throughput. With F3 fixed, how far a run gets in a
fixed wall-clock budget through the DLL-injection section is non-deterministic. A
post-F3 re-characterization (see **F1**) found the slow probe (`Walking process
memory with GetModuleInformation`) is **not** the documented cooperative-scheduler
`RtlpBackoff` livelock, and — correcting a wrong intermediate conclusion — **not**
a cyclic-free-list heap loop either: the main thread progresses (one traced run
ran past that probe to the later `.NET module structures` probe), it is just
**slow** grinding real ntdll heap code under emulation. So the residual x64
terminus is **F2 throughput** on the heap-heavy probes, plus the still-open pre-F3
`RtlpBackoff` livelock. Getting further also surfaced a **second injected-library
FP** in the `hidden modules` probe (mapped-file path returned as `\??\C:\…`
instead of `\Device\…`), fixed this pass. F2 raw per-instruction speed is healthy
and F3's NLS re-open storm — one of the two big wall-time sinks — is now gone.

## Reproduction

Dependencies are read relative to `AppContext.BaseDirectory` (next to
`Brovan.dll`): `WindowsLibs/*.dll` (+ `SysWOW64/`), `WindowsLibs/*.nls`,
`WinReg/{SYSTEM,SECURITY,SOFTWARE,HARDWARE,SAM}`, and the auto-generated
`apisetmap.bin`. Use `scripts/Export-BrovanDeps.ps1` on a real Windows box and
`scripts/Import-BrovanDeps.{ps1,sh}` on the analysis host.

Drive one sample to completion and exit cleanly (no interactive prompt spam):

```bash
printf 'start\nexit\n' | dotnet Brovan.dll /path/to/al-khaser_x64.exe
```

Harness gotchas learned the hard way:

- Build with a **.NET 9 SDK** (9.0.x), not a .NET 8 SDK — even though the target
  framework stays net8.0. The `Brovan.Generators` Vulkan source generator needs
  Roslyn 4.10; an 8.0.1xx SDK loads it against Roslyn 4.8, silently emits
  nothing, and the build then fails with ~23 `CS0103 'BvkMK' /
  'BrovVulkStructMeta' does not exist` errors that look like broken source but
  are just the wrong SDK. If `which dotnet` resolves to a .NET 8 SDK, put the
  9.0 SDK ahead of it on `PATH` first.
- `dotnet build` writes to `bin/Release/net8.0/`, **not** `bin/Release/net8.0/linux-x64/`
  (the deps live in the latter). After building, copy `Brovan.dll` across, or
  run from `net8.0/` with the deps beside it. Running the stale `linux-x64`
  binary silently masks code changes.
- To measure throughput deterministically, `RunMlfqScheduler(MaxTotalInstructions:)`
  bounds a run cleanly (the scheduler returns once the quantum-estimated `Total`
  crosses the bound). `WindowsGuest.Start` calls it with no bound; a temporary
  env-gated override plus a stopwatch around it gives reproducible insn/s.
  Silent (`-s`) redirects stdout **and** stderr, so route any measurement print
  to a file, and note that `-s` runs call `Emulator.Start()` directly (bypassing
  the `case "start"` dispatcher), so instrument inside `Start`/the guest, not the
  menu.
- `-c run` executes `ExecuteCommand("run")`; if the emulator was not `start`ed
  first the call throws and is swallowed, dropping to the REPL prompt with no
  emulation. Use the `start` command (it runs the full guest to termination).
- `RunEmulator` sets `Flags = Silent ? 0 : LogFlags.All`. Run **without** `-s`
  to keep the syscall / `[ENTRY]` trace; `-s` silences everything.
- After the guest terminates, the interactive REPL loops printing
  `emu@brovan >` forever (GBs of output) unless stdin delivers `exit`. Pipe
  `printf 'start\nexit\n'`.
- `Console.Out` is auto-flush, so a filtered `grep --line-buffered` capture
  reflects live progress. Do **not** append `| tail` — `tail` buffers to EOF and
  loses everything if the process is killed by `timeout`.
- The emulated process cannot write diagnostics to arbitrary host paths
  (`File.AppendAllText` to `/tmp` or `/home` is sandboxed away and the exception
  is swallowed). Route diagnostics through `Instance.TriggerEventMessage(...,
  LogFlags.General)` to stdout instead.
- Never leave orphaned `dotnet` runs: a stuck emulation pins CPU and skews the
  timing of later runs. Clean orphans, but **do not** `pkill -9 -f Brovan.dll`
  from a shell whose own command line contains `Brovan.dll` — `pkill -f` matches
  the running shell's argv and SIGKILLs itself before `dotnet` even starts (this
  silently swallowed several runs). Kill only real processes, e.g.
  `for p in $(ps -eo pid,comm | awk '$2=="dotnet"{print $1}'); do kill -9 $p; done`.
- Bound each run with `timeout -s KILL <sec>` (plain `timeout` sends SIGTERM,
  which dotnet+Unicorn ignore, so it hangs past the wrapper's own timeout and the
  run is killed with no output). Keep the inner `timeout` under the harness call
  budget, or run the emulation as a background task and poll its log.
- Full `LogFlags.All` still omits the per-syscall `[+] Nt…:` detail lines (those
  are gated on `LogFlags.Syscall`, which is not in the flag set the trace uses);
  the visible `[ntdll] Syscall … executed` and `[ENTRY]` lines are `LogFlags.General`.
  Add temporary diagnostics at `General` level to be sure they are captured.

## Past corrections (landed)

### Dependency tooling (`scripts/`)

`d61c632` / `d6a7da6` add `Export-BrovanDeps.ps1` (Windows), `Import-BrovanDeps.ps1`
(cross-platform pwsh) and `Import-BrovanDeps.sh` (Linux/macOS, no PowerShell) so
a real Windows dependency set can be carried to a Linux analysis host as a single
archive. `ca256ca` fixes a Windows PowerShell 5.1 parse failure (an
assignment-if-expression with a newline `else`). `49f4d32` makes the shell
importer tolerate `unzip`'s exit code 1 (warning on Windows backslash paths)
under `set -euo pipefail`.

### `622ecfa` — ship the NLS tables

**Symptom:** every sample died with exit `0xC0000142` (`STATUS_DLL_INIT_FAILED`)
before its entry point.

**Root cause:** `kernelbase` maps `locale.nls` during init via
`NtInitializeNlsFiles`, which returns `STATUS_FILE_INVALID` when
`C:\Windows\System32\locale.nls` is absent or < 0x40 bytes. The dependency
bundle shipped DLLs but not the `*.nls` tables.

**Fix:** the export script now ships all `System32\*.nls`; both importers warn
if `locale.nls` is missing.

### `754b51b` — real VC++ runtime in the curated DLL set

**Symptom:** samples that statically pull the MSVC runtime failed to bind
imports.

**Fix:** add `msvcp140*`, `vcruntime140*`, `concrt140`, `vccorlib140` (plus
`mpr`, `wmiclnt`) to the curated export list, sourced from a real VC++
redistributable rather than Wine stubs.

### `e70c2b5` — apiset map: `heap-obsolete` resolves to `kernel32`

**Symptom:** `0xC0000139` (`STATUS_ENTRYPOINT_NOT_FOUND`) in the loader; the
guest reported `NtRaiseHardError` for `GlobalSize` / `GlobalUnlock` imported from
`gdi32full.dll` / `USER32.dll`.

**Root cause:** on a non-Windows host, `CrossGenerator` builds the ApiSet map
from `BinaryEmulatorHelper.ApiSetMap`. The contract
`api-ms-win-core-heap-obsolete-l1-1-0.dll` was mapped to `KERNELBASE.dll`, but
the legacy `Global*` / `Local*` heap functions live **only** in `kernel32.dll`
(kernelbase exports just `GlobalAlloc`/`Free` + a subset of `Local*`). The
version-independent apiset hashing in `CrossGenerator` was verified correct
first — this was a single wrong mapping value, not a resolver bug.

**Fix:** map `api-ms-win-core-heap-obsolete-l1-1-0.dll → kernel32.dll`.

**Validation:** al-khaser's own entry point + CRT startup run; 13.5 M
instructions; 74 distinct syscalls.

### `b15fab0` — seed always-present Windows system images into the VFS

**Symptom:** al-khaser reached `terminate()` / `__fastfail` (`0xE06D7363` C++
exception path) at ~13.5 M instructions, from an uncaught
`std::filesystem_error`.

**Root cause (realism coherence gap):** `WinSyscallsHelper.cs` advertises a
synthetic process table whose entries carry real image paths — the parent is
`explorer.exe` at `C:\Windows\explorer.exe`, plus the System32 core services.
al-khaser retrieves its parent image and calls
`std::filesystem::equivalent(parent, "C:\Windows\explorer.exe")`. Both operands
resolve to that path, but the file was not backed in the VFS, so `NtCreateFile`
returned `STATUS_OBJECT_NAME_NOT_FOUND`, `equivalent` threw, and al-khaser did
not catch it (on a real install `explorer.exe` always exists, so the throw never
happens). Confirmed by instrumenting `NtCreateFile`:
`raw='\??\C:\Windows\explorer.exe' fileExists=False → OBJECT_NAME_NOT_FOUND`.

**Fix:** `GeneralHelper.IO.EnsureWindowsBaseFilesystem` (mirror of the existing
`EnsureLinuxBaseFilesystem`) seeds a minimal but valid PE32+ stub for
`C:\Windows\explorer.exe` and the always-present System32 executables into the
virtual `C:` drive at startup. The stub only needs to open/stat/parse as a real
PE; it is never executed. Because both `equivalent` operands are the same guest
path they resolve to the same backing file, so `equivalent` returns `true`
("launched by explorer" = bare metal) — the correct answer.

**Validation:** `equivalent` succeeds; al-khaser runs ~69 % further to 22.8 M
instructions and begins printing its detection results.

### `4b9540f` — NtReadVirtualMemory addresses arg1/arg2 by value

**Symptom:** after the VFS fix, al-khaser died with `0xC0000005`
(`STATUS_ACCESS_VIOLATION`). The single faulting instruction was
`mov rdi, QWORD PTR [r14]` at al-khaser `0x14000D0F0` with `r14 = 0` — a read of
`[NULL]` inside the loop that iterates the module-result vector
(`_Myfirst`=NULL, `_Mylast`≠NULL — a corrupted `std::vector`). The strings
`" [!] Injected library: %S"` / `" [!] Error reading entry."` identify it as the
**injected-library** check, which walks the PEB loader lists and reads each
0x88-byte module entry via `NtReadVirtualMemory`.

**Root cause:** the current-process branch of `NtReadVirtualMemory` treated
`BaseAddress` (arg1) and `Buffer` (arg2) as pointers-to-pointers
(`BaseAddress = ReadMemoryULong(arg1)`), but the syscall passes both **by value**
— arg1 is the address to read from, arg2 is the destination buffer. The
cross-process branch already writes to `BufferPtr` directly, confirming the
dereference was the bug. Raw-arg trace:
`arg1_base=0x100212960 size=0x88 deref(*arg1)=0x1002127D0 arg1_directly_mapped=True`
— Brovan read from `0x1002127D0` instead of `0x100212960`, corrupting the module
entries, which left the vector in a bad state and faulted on iteration.

**Fix:** use `BaseAddressPtr`/`BufferPtr` directly, drop the "pointer must be
mapped" guards that only made sense under the wrong interpretation, and populate
the optional `NumberOfBytesRead` out-parameter (arg4). Benefits **all**
`ReadProcessMemory`-on-self, not just al-khaser.

**Validation:** module enumeration completes (96 entries = 3 PEB lists ×
32 modules); the AV is gone.

### `ed5b1ab` — present the sample under a realistic guest image path

**Symptom:** two facets of one root cause. (a) al-khaser creates its `log.txt`
next to the executable (`NtCreateFile` disposition 5 = `FILE_OVERWRITE_IF`) and
got `STATUS_OBJECT_NAME_NOT_FOUND`; observed path `\??\\tmp\...\alkhaser\x64\log.txt`.
(b) `GetModuleFileName(NULL)` / the main-module NT path / `std::filesystem::equivalent`
on the own image all read back a non-Windows path.

**Root cause:** a sample is loaded from an arbitrary *host* location
(`/tmp/.../al-khaser_x64.exe` on the Linux analysis host), and that host path
leaked straight into the guest — the PEB `ProcessParameters` `ImagePathName` /
`CommandLine` / `CurrentDirectory` (`WindowsGuest.PrepareWinEnvironment`) and the
main module's `Path` (`WindowsGuest.InitializePE`) were all set from
`BinaryFile.Location`. `\tmp\...` resolves to no drive, so any create/open relative
to the sample's own directory failed.

**Fix:** `WindowsGuest` resolves the main image to a synthetic guest path
`C:\Users\<user>\Desktop\<leaf>` (stable per-run username shared with the
environment block, so `USERNAME`/`USERPROFILE`/`TEMP` and the image path agree),
backs the sample bytes in the virtual `C:` drive
(`GeneralHelper.IO.SeedGuestImageFile`) so the guest can open/stat/read its own
image and drop siblings, and computes the current directory with Windows-path
semantics (`Path.GetDirectoryName` does not treat `\` as a separator on Linux).
A host-absolute Windows path (a real `C:\` sample on Windows) is kept verbatim.
`EmulationMenu` now finds the main module via `WindowsGuest.MainModuleBase`
instead of matching on `BinaryFile.Location` (which no longer equals `Module.Path`).

**Validation:** image path is `C:\Users\<user>\Desktop\al-khaser_x64.exe`, the
`log.txt` create succeeds in the VFS, the own image is backed, and the run
reaches full depth with no "Couldn't determine the main module" regression.

### `2f6e5ae` — QueryDosDevice / ProcessImageFileName / NLS-path prerequisites for the anti-injection check

**Symptom:** al-khaser's DLL-injection check (`ScanForModules::IsBadLibrary`)
flags **every** legitimately-loaded module — and the sample's own exe — as
"injected".

**Root cause (fully traced).** `IsBadLibrary(path)` returns *legit* only if the
module path matches the System32 device path, the System32 drive path, or the
process's own image path. It normalises device↔drive with `QueryDosDevice` and
reads the own image with `GetProcessImageFileName`. Three prerequisites were
broken:

1. `QueryDosDevice("C:")` returned **0**. Its kernelbase implementation opens the
   `\??` DOS-devices object directory via `NtOpenDirectoryObject`, then the `C:`
   symlink relative to it. `NtOpenDirectoryObject` only knew `\KnownDlls*` /
   `\BaseNamedObjects` / `\RPC Control`, so it returned `STATUS_NOT_SUPPORTED` and
   the whole `if (QueryDosDevice(...) > 0)` block was skipped → *everything*
   flagged. **Fixed** by registering a `DOS_DEVICES_DIRECTORY` handle for the
   `\??` / `\GLOBAL??` / `\DosDevices` / `\Sessions\0\DosDevices` aliases; the
   relative `\??\C:` symlink already resolves to `\Device\HarddiskVolume1`.
2. `NtQueryInformationProcess(ProcessImageFileName)` returned `BinaryFile.Location`
   (the host path) instead of the NT device form of the guest image. **Fixed** via
   `DosPathToNtDevicePath` → `\Device\HarddiskVolume1\Users\<user>\Desktop\<leaf>`,
   coherent with what `QueryDosDevice("C:")` resolves the C: link to.
3. `C:\Windows\Globalization\Sorting\SortDefault.nls` (the linguistic sort table
   that kernelbase's `CompareString` — reached by `StrCmpNIW`/`StrCmpIW` — maps to
   build its collation) returned `STATUS_OBJECT_NAME_NOT_FOUND`; the WindowsLibs
   resolver only mapped System32 / SysWOW64 / KnownDlls. **Fixed** by resolving any
   `C:\Windows\Globalization\...` file by leaf to the shipped flat `.nls` set.

**How it was traced:** temporary `[ENTRY]`-hook instrumentation dumped the exact
SHLWAPI `StrCmpNIW`/`StrCmpIW` arguments + count, showing e.g.
`StrCmpNIW("C:\Windows\System32\", "C:\Windows\System32\KERNEL32.DLL", n=20)` —
a byte-identical 20-char prefix that must compare equal — yet the module was
flagged. `GetSystemDirectory` (`C:\Windows\System32\`), `QueryDosDevice`
(`\Device\HarddiskVolume1`) and `GetProcessImageFileName`
(`\Device\HarddiskVolume1\Users\<user>\Desktop\al-khaser_x64.exe`) all read back
correct after the fixes, and the sort file now resolves. All diagnostics were
reverted before commit.

**Residual at the time (now fixed by `b205488`, above).** With these
prerequisites correct the false positive still stood: the case-insensitive
comparison returned "not equal" for equal strings. `StrCmpNIW`/`StrCmpIW` are
thunks → apiset `api-ms-win-core-shlwapi-obsolete` → `kernelbase!StrCmpNIW`,
whose real code routes the compare through the NLS sort-table dispatch and
returns `CompareString - 2`. The failure was one layer lower than this note
assumed: the sort file did **not** actually open — the ≈4684×/run "opens" were
kernelbase *re-attempting* a failing `CreateFileW` on `sortdefault.nls` every
compare (a Linux `Path.GetFileName` leaf-extraction bug in Brovan's resolver, see
`b205488`). Fixing the open fixes the collation; F3 is closed.

### `bc151f0` — memoize the per-instruction IRETQ probe (throughput)

**Symptom:** the per-instruction code hook (`InstructionHandler`) issued a
`uc_mem_read` on **every 2-byte instruction** to test for the 64-bit `IRETQ`
opcode (`48 CF`). A clean in-binary A/B on the CPU-bound phase (5M-instruction
bound, 6 interleaved runs, silent) measured that read at **~11 %** of run time
(median 1437 ms → 1284 ms with the memo).

**Why the read exists (and can't just be deleted):** Brovan emulates `IRETQ`
manually (pop RIP/RFLAGS/RSP from the trap frame) because Unicorn's own `IRETQ`
diverges in the flat long-mode setup. Proven: with the manual path disabled,
al-khaser_x64 bails **14M instructions early** (10.2M vs 24.1M) — it is
load-bearing, so the fix must preserve the exact detection, not remove it.

**Fix:** memoize the probe in a direct-mapped table keyed by code address
(`BinaryEmulator.WindowsBridge.cs`). Mapped code bytes are immutable for the
life of a mapping, so a slot hit reuses the prior result; a miss (address
mismatch, incl. eviction by collision) always re-reads and stays correct. The
only unmodelled case is self-modifying code that rewrites an already-cached
address into/out of `48 CF`, which no real code produces.

**Validation:** the memoized build reaches the same **~24.07M-instruction**
terminus as before (vs the 10.2M divergence when the `IRETQ` path is removed),
with **0 new faults** across al-khaser's load of 34 modules. This is a
throughput fix — it does not move the terminus.

### `b205488` — NLS sort-table open on Linux (`Path.GetFileName` on a backslash path)

**Symptom (the F3 false positive).** al-khaser's DLL-injection check flagged
**every** legitimate System32 module (ntdll / kernel32 / kernelbase) *and* the
sample's own exe as "injected", because kernelbase's case-insensitive
`CompareStringW` / `StrCmpNIW` / `StrCmpIW` returned a **constant error** for
every input — equal and unequal alike.

**Actual root cause — and a correction to the earlier ~10-layer chase.** The
prior investigation traced the failure down to `kernel32!SortGetHandle`'s worker
`0xa238` and recommended tracing *its* return-0 branch and verifying the sort
**GUID/version** fields against the shipped `sortdefault.nls` header. That was a
**red herring**: this pass instrumented `SortGetHandle`'s internals directly and
found the worker never reaches the version/validator logic at all — it fails at
the very first step, the **file open**. `SortGetHandle`'s init (`kernel32`
`0xb49c`) builds the path `C:\Windows\Globalization\Sorting\sortdefault.nls` and
opens it via `CreateFileW → CreateFileMappingW → MapViewOfFile` (`0xb820`);
**`CreateFileW` returned `INVALID_HANDLE_VALUE`**, so the sort load returned 0,
the per-locale sort registry never populated, and every collation errored. (The
version gate was never the problem — arithmetically it *passes*: the worker's
`(loadedVer ^ reqVer) & 0xffffff00` check on `0x00060305 ^ 0x000603ff` is 0. So
swapping in a "more genuine" `sortdefault.nls` would **not** have fixed it; the
shipped Wine-generated table is format- and version-compatible with this 19041
kernelbase, and its validator (`0xb714`) accepts it once it can be opened.)

The open failed inside **Brovan's own** read-path resolver, not the guest NLS
code. `GeneralHelper.ResolveHostPath`'s WindowsLibs fallback extracted the file
leaf with `Path.GetFileName`, which splits on `Path.DirectorySeparatorChar`. On
Linux that is `/`, so on the backslash guest path
`C:\Windows\Globalization\Sorting\sortdefault.nls` it returned the **whole
string** as the "leaf"; the case-insensitive WindowsLibs leaf index then missed,
resolution fell through to a non-existent `VirtualFS/…` path, and the open
failed. The `.nls` files ship flat in `WindowsLibs` and resolve correctly once
the leaf is extracted with the right separator. (System32 DLL loads were
unaffected because they resolve via `TryResolveFromWindowsLibsRelative` /
`CombineWindowsRelativePath`, which converts separators, and never needed the
buggy leaf path.)

**Fix.** Add a separator-agnostic `WindowsLeafName` helper (splits on both `\`
and `/`) and use it for every Windows-style leaf extraction in the resolver: the
`Globalization\` branch (the `sortdefault.nls` path — the F3 fix), the two
`\KnownDlls\` branches in `ResolveHostPath`, the `\KnownDlls\` branch in
`TryResolveFromWindowsLibs`, and the relative-path leaf fallback in
`TryResolveFromWindowsLibsRelative` (all the same latent cross-platform bug).
`Path.GetFileName` is kept only where the input is a real host path (the
WindowsLibs index build over `Directory.EnumerateFiles`).

**Validation — traced at the syscall/library level (all diagnostics reverted).**
- Resolution now maps the guest path to `WindowsLibs/sortdefault.nls`,
  `NtCreateFile` reports `FileExists=True`, `CreateFileW → 0x418` (valid handle),
  `CreateFileMappingW` / `MapViewOfFile` succeed, the validator (`0xb714`)
  returns 1, and `kernel32!SortGetHandle` reaches its success tail (fills the
  sort object vtable). It runs **once** — the ≈4684×/run re-open storm is gone.
- Watching kernelbase's compare exports at runtime (base resolved lazily — note
  kernelbase maps *after* the initial ntdll/kernel32 bootstrap, so it is absent
  from `WinModules` early), the returns are now correct instead of the constant
  error:

  | call | before | after |
  |------|--------|-------|
  | `StrCmpIW` byte-identical | `-2` | **`0`** (equal) |
  | `StrCmpIW` different | `-2` | **`-1`** (less) |
  | `CompareStringW` | `0` (error) | **`1`/`2`/`3`** (`CSTR_LESS/EQUAL/GREATER`) |
  | `StrCmpNIW("C:\Windows\System32\", "C:\Windows\SYSTEM32\ntdll.dll", n)` | `-2` | **`0`** (prefix equal, case-insensitive) |

  That last row is the FP itself: al-khaser tests each loaded module's path
  against the System32 prefix; with the compare fixed, ntdll / kernel32 /
  kernelbase now match `System32\` and are correctly recognised as legitimate
  rather than reported as injected.

**Method note (cost this pass, and the earlier one).** Brovan's per-instruction
hook fires *before* the watched instruction executes, so to read a call's result
you must watch the **return address** and read `rax` there — never read a
destination register *at* a `mov dst, rax`. The earlier pass's wrong "resolver
returns NULL for en-US" claim came from violating this; the earlier "trace the
sort version" recommendation came from stopping the trace at `SortGetHandle`
without instrumenting the file open one layer in. When a multi-layer guest-code
trace bottoms out, check whether the failure is actually in an emulator-side
syscall/resolver (here, `NtCreateFile` path resolution) before theorising about
the guest's deeper logic.

### Scheduler livelock watchdog (F1 mitigation — safe recovery + diagnostic + opt-in escape)

**Motivation.** The pre-F3 `RtlpBackoff` livelock (F1) is a non-deterministic
cooperative-scheduler hazard: one ntdll thread free-runs the `rdtsc`+`pause`
SRW/critsec backoff spin forever while its peers are parked in
`NtWaitForSingleObject` on handles that never get signalled in that particular
interleaving. Because the spinner stays *runnable*, the scheduler happily feeds
it full quanta and the run burns hundreds of millions of no-progress
instructions to the wall-clock timeout with no diagnostic. The full source-level
fix (find the exact signal/wait pairing whose release never propagates and make
signal-before-wait always leave consumable state) needs a deterministic repro to
do safely — see F1. This change adds the generic, low-risk scheduler-level net
the F1 note recommends ("force a wakeup re-scan or advance virtual time … a
scheduler deadlock/livelock detector").

**Discriminator (why it does not fire on the healthy slow-heap path).** A slice
is classified as a *frozen spin* only when the running thread completes a
**full quantum** yet ends within `LivelockSpinRipWindow` (0x40) of where it
started, **is the only runnable thread**, and **≥1 peer is parked in `Waiting`**.
Forward-progressing code breaks this every slice: over a full 200k-instruction
quantum a real code path moves its RIP far (the F2 heap probe traverses
`RtlAllocateHeap` + helpers + `memset` and returns to callers), or it yields via
a syscall (which truncates the slice, so it never completes a full quantum in
place). Only a genuine userland spin ends a full quantum essentially where it
began. The episode counter resets the instant the RIP moves, a peer becomes
runnable, or the thread yields, so it climbs unboundedly **only** for a true
infinite spin.

**Action (escalating, always-safe first).** After `LivelockNudgeSlices` (256)
consecutive frozen slices, and every 256 thereafter, the scheduler:
1. emits **one** `LogFlags.General` diagnostic per episode naming the spinning
   thread (`module+offset` when resolvable) and every parked peer with its
   resume RIP, wait handles and deadline — the exact chokepoint the next F1 pass
   would otherwise have to re-instrument by hand;
2. runs the **safe recovery**: a full `UpdateMlfqWakeups` re-scan (recovers a
   missed/late wakeup — F1's primary hypothesis) plus a virtual-time advance to
   the nearest finite deadline. Neither can perturb a thread that needs no peer
   to progress (the re-scan only touches genuinely-blocked waiters; the
   time-advance only moves *finite* deadlines, and the idle thread-pool workers
   wait on `WorkerFactory` with no deadline), so a false-positive spin
   classification is a harmless no-op. If the recovery wakes a peer,
   `HasOtherRunnableThread` flips next slice and the episode self-clears.

**Opt-in bounded escape.** `BinaryEmulatorSettings.LivelockEscapeSlices`
(default **0 = disabled**) lets the operator/harness cap a genuinely
unrecoverable interleaving: when non-zero, once the spin persists that many
frozen slices with nothing changing, the scheduler returns cleanly so the run
reaches a bounded, diagnosable terminus instead of hanging to the wall-clock
timeout. It is off by default and must be set larger than any legitimate
self-completing tight loop the sample runs (a big `memset` also pins its RIP) —
it exists for a calibrated hunt, not as a default behaviour change. The menu
wires it from the env var **`BROVAN_LIVELOCK_ESCAPE_SLICES`** (unset / unparseable
⇒ 0), so it is reachable without a rebuild; the escape is evaluated at the
256-slice nudge boundaries, so the effective bail count rounds up to the next
multiple of 256.

**Validation (behavioural — al-khaser + a deterministic repro).** Compiles clean
(`dotnet build -c Release`, net8.0 via a .NET 9 SDK) and was **run end-to-end**
against `al-khaser_x64.exe` with the real Windows dependency set + Unicorn 2.1.4:

- *No misfire on the real, progressing sample.* Four independent runs plus a
  baseline built at the parent commit all reach the same terminus —
  **~149 M instructions** (one interleaving 105 M; the depth is non-deterministic
  as documented), `0xC0000005`, 397 injected-library lines — with **zero**
  watchdog output. The added path is never entered on al-khaser, so the build is
  byte-for-byte behaviourally identical to baseline there (the discriminator
  never accumulates 256 pinned full-quantum slices because the sample keeps
  progressing).
- *Positive path proven with a deterministic livelock repro.* A minimal x64 PE
  whose main thread spins (`jmp $`) after spawning a worker that parks on
  `Sleep(INFINITE)` reproduces the exact "only-runnable spinner + blocked peers"
  shape. With the watchdog on it emits the precise diagnostic —
  `Scheduler livelock suspected: thread N spinning at spin2.exe+0x102C … Waiters:
  tid=… handles=[0x64] tid=… deadline=…` — naming the spinner (module+offset) and
  both parked peers with their handles/deadlines. With the escape off (default)
  the run keeps spinning (recovery cannot resolve the effectively-infinite waits);
  with `BROVAN_LIVELOCK_ESCAPE_SLICES=400` it prints
  `Scheduler livelock escape: … spun 512 frozen slices … terminating scheduler.`
  and **exits cleanly (rc=0)** instead of hanging to the timeout.

This upgrades the earlier reasoning-only validation to a behavioural one on both
the negative (no regression on the real sample) and positive (detect → diagnose
→ escape) sides. The source-level lost-wakeup fix (F1 steps 1–3) still stands —
the recovery only recovers the recoverable subclass — but the watchdog now
demonstrably turns a silent hang into an actionable, bounded terminus.

**Environment note (deps-bundle gap).** The dependency bundle used here (build
19044) ships the codepage `C_*.NLS` tables but **not**
`Globalization\Sorting\SortDefault.nls`. Without it the F3 NLS-collation fix has
no file to open, so the injected-library false positive reappears (al-khaser
flags all 61 System32 modules). This is a gap in the dependency **export**, not a
Brovan regression — the F3 code fix (`b205488`) is intact; it just needs the sort
table shipped. Worth adding `SortDefault.nls` to `Export-BrovanDeps.ps1`'s NLS
set for a clean-verdict repro.

### Host-environment fixes (intentionally **not** committed)

These are specific to the Linux build/run host and must not be pushed into
Brovan:

- **Unicorn 2.1.4** (from the PyPI wheel) instead of the distro 2.0.1 — 2.0.1
  rejects `SetTcgBufferSize` (control code 13) at `uc_open`. A local
  save/restore-`_error` workaround was prototyped and reverted; use 2.1.4.
- **.NET 9 SDK** to build (the generator references Roslyn 4.10; .NET 8.0.1xx
  ships 4.8 and fails `CS9057`). The target framework stays net8.0.

## Future corrections (diagnosed, not yet fixed)

### F1 — Cooperative-threading livelock (non-deterministic)

**Symptom:** after `4b9540f`, al-khaser does not reach a clean terminus within
240 s. Two distinct, timing-dependent outcomes were observed by instrumenting
`RunMlfqScheduler` (periodic dump of every thread's id / state / RIP / waited
handle + object type):

- *Progressing run:* the main thread advances (RIP changes across dumps,
  ntdll → guest module), reaches 96 enumerated modules, `total` climbs steadily.
  Two thread-pool workers wait on `WinWorkerFactory` handles — idle, normal.
  This run is **not** deadlocked, just slow (see F2).
- *Livelocked run:* one ntdll thread spins forever in `RtlpBackoff`
  (RIP pinned at guest ntdll `0x5CDB6` — the `rdtsc` + `pause` spin-wait used by
  SRW-lock / critical-section acquisition), while two threads are parked in
  `NtWaitForSingleObject` (SSN 4, resume RIP `0x9CDF4`) on handles that are never
  signalled. The spinner waits for a lock held by a parked thread whose wait
  object never gets signalled **in that particular interleaving**.

**Root-cause hypothesis:** a lost-wakeup / stale-lock race in the cooperative
wait/signal path. On real preemptive Windows the lock holder is eventually
scheduled, releases, and the waiter wakes; under Brovan's cooperative MLFQ the
signalling never lines up for some interleavings.

**Ruled out (checked):** `NtSetEvent` persists the signalled state
(`Ev.Signaled = true`), so event signals are not lost across a signal-before-wait.
`NtWaitForAlertByThreadId` / `NtAlertThreadByThreadId` correctly persist a
pending alert (`AlertByThreadIdPending` is checked before parking), so the
modern SRW/critsec alert path has no trivial lost-wakeup.

**Recommended approach:** this is a scheduler + synchronization-model effort, not
a targeted stub fix, and is high-risk for regressing other multi-threaded
samples. Steps: (1) build a deterministic repro (fixed scheduling seed / single
worker); (2) trace every signal/wait pairing for the two stuck handles to
identify which release never propagates; (3) audit the object-signalled-state
vs parked-waiter-wakeup split for **every** waitable type (`WinEvent`,
`WinSemaphore`, `WinMutex`, `EmulatedThread`, `WinTimer`, keyed events,
`WinWorkerFactory`), ensuring a signal that arrives before the wait always leaves
consumable state. Consider a scheduler deadlock/livelock detector: when the only
runnable thread is spinning in a known ntdll backoff and all others are blocked,
force a wakeup re-scan or advance virtual time.

**Landed mitigation (the detector half of step 3's last sentence).** The
scheduler now carries a generic **livelock watchdog** (see *Past corrections* →
*Scheduler livelock watchdog*): it recognises the "only runnable thread completes
full quanta at a pinned RIP while ≥1 peer is parked" shape, emits a per-episode
diagnostic naming the spinner + every stuck waiter's handles (the exact input
step (2) asks for, now produced automatically), and performs the safe recovery
(full wakeup re-scan + finite-deadline time advance). A discriminator keyed on
*full-quantum + RIP-pinned* keeps it from firing on the progressing slow-heap
interleaving, and an opt-in `LivelockEscapeSlices` (default off) can bound a
genuinely unrecoverable interleaving to a clean terminus. This does **not**
replace the source-level fix — steps (1)–(3) still stand for the lost-wakeup
that the recovery can't recover — but it turns the silent multi-minute hang into
an actionable signal and recovers the recoverable subclass. Now **behaviourally
validated** (see *Scheduler livelock watchdog* → *Validation*): four al-khaser
runs + a parent-commit baseline confirm zero misfire on the progressing sample
(identical ~149 M-instruction / `0xC0000005` terminus), and a deterministic
spin-PE repro proves the detect → diagnose → escape path (clean `rc=0` under
`BROVAN_LIVELOCK_ESCAPE_SLICES`).

**Post-F3 re-characterization (2026-07, corrects the framing above).** After the
F3 fix (`b205488`) removed the `sortdefault.nls` re-open storm, the instruction
interleaving changed, and a fresh scheduler-state trace (dump every live
thread's state / RIP / module / spin-score / wait-objects every 50 slices) shows
the observed al-khaser x64 stall is **not** the `RtlpBackoff` livelock described
above. In the runs sampled this pass:

- The **main thread is Running and progressing** (`spin=0`, RIP moves through
  ntdll/ucrtbase each sample) — it is not pinned in a backoff spin.
- The two thread-pool workers are parked on `WorkerFactory`
  (`WorkerFactoryWaitActive=true`, `STATUS_PENDING`) — idle-normal, exactly the
  doc's "progressing run". **Nothing** sits in the `RtlpBackoff` region
  (`0x5CDB6`).

The current terminus, and the correction of a wrong intermediate conclusion:
al-khaser reaches `Walking process memory with GetModuleInformation` and the main
thread spends a long time in the ntdll heap manager (`RtlAllocateHeap` + helpers
around RVA `0x2B3E2..0x2B426`, plus `memset`).

- **Not a `VirtualQuery` walk** — `NtQueryVirtualMemory` is **never called** while
  the run sits on that probe (instrumented at the syscall's top), so the classic
  `while(VirtualQuery(addr)) addr += RegionSize;` non-termination is ruled out.
  (The `MemoryBasicInformation` branch *did* have a latent non-termination bug —
  above the highest mapped region it returned `STATUS_SUCCESS` + `MEM_FREE` size
  `0x1000` forever instead of failing past `MmHighestUserAddress` — **fixed
  separately in `d1f5d3a`**; not what al-khaser hits here.)
- **NOT a cyclic free-list (a prior revision of this note, `4fc943a`, was
  wrong).** That revision claimed the free-block search at `0x2B3E2` was stuck in
  a cyclic walk. A raw sequence trace of that loop disproved it: `0x2B3E2` fires
  only ~72× across the whole probe, with **13 distinct `rsp` values and varying
  request sizes** — i.e. the search runs *finitely* and is re-invoked per
  allocation, not one infinite walk. The earlier "cycle" was a detector artefact:
  it flagged the free-list **head** node recurring as the start of *separate*
  finite searches as if it were a revisit within one walk. The request sizes grow
  briefly (`0x167→0x218→0x323→0x4B2`, ×1.5) then **plateau at `0x4B2`** — no
  unbounded growth either.
- **It is slowness, not a loop.** With the trace on, one run **progressed past**
  `GetModuleInformation` (→ `GOOD`) and on to the later `Walking process memory
  for hidden modules` / `.NET module structures` probes — the earlier "stuck at
  line 65" runs were simply slow (real ntdll heap code, per-alloc cost in the
  hundreds-of-thousands to ~1M emulated instructions, ×many allocations). How far
  a run gets in a fixed wall-clock budget is non-deterministic. So the residual
  al-khaser x64 terminus is **F2 throughput** on the heap-heavy probes, plus the
  pre-F3 `RtlpBackoff` livelock which is still a real (separate, non-deterministic)
  hazard — not a heap-corruption bug.

**End-to-end terminus (2026-07, real harness).** With the exported deps + Unicorn
2.1.4 harness now available, four al-khaser_x64 runs + a parent-commit baseline
consistently reach a **much deeper endpoint than the 22.8 M-instruction line the
top table records**:

- **~149 M instructions** (105 M in one interleaving; depth is non-deterministic
  as documented) — **6.6× beyond** the doc's `4b9540f`-era ceiling.
- **48 al-khaser probe verdicts printed** every run (38 `GOOD` / 10 `BAD`), with
  the `BAD` set stable across runs and identical to baseline. All 10 `BAD` are
  the injected-library FP: `cfgmgr32.dll`, `bcrypt.dll`, `POWRPROF.dll`,
  `UMPDC.dll`, `cfgmgr32.dll` again (× 2 each × 5 modules = 10 flags) — the F3
  collation gap reappears purely because the shipped deps bundle is missing
  `SortDefault.nls` (see script fix below), **not** a Brovan regression: the F3
  code fix (`b205488`) is intact and re-verified.
- **Termination pattern is consistent**: a fault deep in the DLL-injection /
  hidden-modules memory-walk probe → `ntdll!KiUserExceptionDispatcher` →
  `VCRUNTIME140!__C_specific_handler` → `ucrtbase!_seh_filter_exe` →
  `NtTerminateProcess(0xC0000005)`. rc = 0 (the process exits cleanly through the
  guest's own SEH machinery — a natural terminus at "al-khaser catches a fault
  and terminates itself", not a Brovan crash).
- The exact faulting page is run-specific (`0x100209000` / `0x1002A9000` /
  a null-read in one interleaving), all inside the same `0x100120000`-based
  allocation family — a memory-model coherence question worth its own pass but
  not chased here: the runs all reach the same terminus category, and the
  livelock watchdog is silent throughout every one.

**Deps-bundle fix landing with this note** (`scripts/Export-BrovanDeps.ps1` +
importer validators). The export script's NLS copy globs `System32\*.nls`, but
the sort table the F3 fix (`b205488`) needs to open for `CompareStringW` /
`StrCmpNIW` — `SortDefault.nls` — is **not in System32 at all**: it lives at
`%WINDIR%\Globalization\Sorting\SortDefault.nls` (one architecture-independent
file, shared by the x64 and x86 views), so the System32 glob never picks it up.
Bundles exported from the older script (including the one used for the runs
above) trip the F3 injected-library FP on every re-import, even though the code
fix is intact. The export script now copies `SortDefault.nls` from
`%WINDIR%\Globalization\Sorting` into both the x64 (`WindowsLibs\`) and x86
(`WindowsLibs\SysWOW64\`) views, and both importers (`Import-BrovanDeps.ps1` /
`.sh`) warn when it is absent so operators reconciling an older bundle notice
before running. Brovan's `\Globalization\...`-by-leaf resolver (commit `2f6e5ae`)
already maps the file wherever it lands in `WindowsLibs\`, so no runtime change
is needed.

**Complete missing-file inventory (resolver-instrumented, this pass).** To settle
"what else is the bundle short of", the read-path resolver was instrumented to log
every `*.nls` / `*.dll` guest open that falls through to a non-existent VirtualFS
path. Across a full run al-khaser touches exactly three unshipped files, all now
covered by the curated-set / NLS fixes:

- `Globalization\Sorting\SortDefault.nls` — the F3 collation table (requested
  **once** per run now, confirming the F3 code fix ended the pre-`b205488`
  re-open storm — the residual is purely the missing file).
- `WUDFPlatform.dll` — al-khaser resolves `WudfIs{Any,Kernel,User}DebuggerPresent`
  from it for its WUDF debugger checks.
- `faultrep.dll` — al-khaser's Windows-Error-Reporting-based probe.

The two DLLs are now in the `Export-BrovanDeps.ps1` curated set. Their absence is
**low-severity** (the `GetProcAddress` calls return NULL, so those specific probes
silently no-op rather than exercising the real detection path — they do not fault
or change the terminus), but shipping them closes the last fidelity gaps the
al-khaser workload exposes in the dependency bundle. No other `*.nls` / `*.dll`
is requested-but-missing.

**Unimplemented ntdll syscalls the run exercises.** Separately from missing files,
al-khaser reaches a handful of ntdll syscalls Brovan answered with
`STATUS_NOT_SUPPORTED`. The SSN→name map is authoritative (extracted from the
shipped 19044 ntdll stubs): `0x19E NtSetInformationVirtualMemory` (31×),
`0xFB NtGetWriteWatch` (5×), `0x162 NtQueryTimerResolution`, `0xA5
NtCreateDebugObject`, `0x1BD NtSystemDebugControl`, `0x179 NtResetWriteWatch`,
`0x147 NtQueryInformationAtom` (the `0x1037` / `0x105D` ones are `win32u` GUI
syscalls — a different subsystem). Four are now implemented (each auto-registers
via the `IWinSyscall` generator; the SSN is read from the shipped ntdll, so it
tracks the build):

- **`NtSetInformationVirtualMemory` (0x19E)** — advisory VM operations (prefetch /
  page-priority / CFG call-target / working-set / hot-patch / contiguity /
  prepopulate) the MSVC loader/CRT drive; validates the class + `MEMORY_RANGE_ENTRY`
  array + payload and returns success (none observably mutates emulated memory).
- **`NtQueryTimerResolution` (0x162)** — coarsest/finest/current interrupt period,
  kept coherent with the `156250` (15.625 ms) increment `NtQuerySystemInformation`
  already reports.
- **`NtSystemDebugControl` (0x1BD)** — **a real fidelity fix, not just a warning
  removal.** al-khaser's `NtSystemDebugControl` kernel-debugger probe got
  `STATUS_NOT_SUPPORTED` and flagged it **BAD** (detected). Returning the correct
  "no kernel debugger" `STATUS_DEBUGGER_INACTIVE` (the same answer
  `NtQueryDebugFilterState` already gives) flips that probe to **GOOD**: the run
  verdict improved **38 GOOD / 10 BAD → 39 GOOD / 9 BAD**, stable across a full
  149 M-instruction interleaving, terminus unchanged.
- **`NtCreateDebugObject` (0xA5)** — reached lazily via ntdll's `DbgUiConnectToDbg`;
  creating a debug object is not itself a debugger-presence signal (that answer is
  `NtQueryInformationProcess(ProcessDebugObjectHandle)` → `STATUS_PORT_NOT_SET`), so
  it allocates a real handle (new `HandleType.DebugObjectHandle`) and returns it.

**Deferred (need a feature, not a stub).** `NtGetWriteWatch` / `NtResetWriteWatch`
back al-khaser's write-watch technique, which detects an emulator when
`GetWriteWatch` *wrongly succeeds* ("succeeded when it should've failed"). A
faithful implementation needs per-region write tracking — a `MEM_WRITE_WATCH`
allocation flag plus a global memory-write hook to record dirty pages — which has a
per-write throughput cost (the F2 concern) and is a real feature, not a stub. The
current `STATUS_NOT_SUPPORTED` does **not** trip al-khaser's detection (it only
flags on wrong success), so this is a fidelity-only gap, deferred deliberately
rather than papered over with an always-fail stub. `NtQueryInformationAtom` (0x147,
1×) similarly needs atom-table modeling; the `win32u` GUI syscalls are out of scope
for the ntdll pass.

**Verified with a corrected bundle (SortDefault.nls + WUDFPlatform.dll + faultrep.dll
shipped).** Re-exporting with the fixed `Export-BrovanDeps.ps1` and re-running
confirms the deps analysis end-to-end:

- **Injected-library FP eliminated** — with `SortDefault.nls` present the collation
  works, and the 397 `[!] Injected library` lines / the whole class of System32-module
  false positives drop to **0**. `WUDFPlatform.dll` now loads and al-khaser's
  `WudfIs{Any,Kernel,User}DebuggerPresent` resolve and execute (were NULL before).
- **Verdict 44 GOOD / 4 BAD** (from 38/10 at the start of this work). The **only**
  remaining `BAD` is `Thread Hide From Debugger` (flagged for its variants) — a real,
  stable detection, not a false positive; a separate frontier from the deps/collation
  work.
- **New terminus surfaced, non-deterministic.** With the FP-storm gone the flow is
  shorter and different; one interleaving reaches MSVC's `__report_gsfailure`
  (`__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)` / `int 0x29`, `0xC0000409`) at
  ~47 M inside the now-correct module-scan path, another runs past it to ~73 M. That
  GS-cookie mismatch is a **stack-imbalance emulation bug in a path only reachable once
  collation is correct** — not caused by the deps/syscall work, newly exposed by it.
  It joins the non-deterministic `0xC0000005` SEH terminus as an open F2/coherence
  frontier; the livelock watchdog stays silent throughout.

**Bonus finding surfaced by getting further — a second injected-library FP.** The
`Walking process memory for hidden modules` probe reported every System32 module
(`KERNEL32.DLL`, `KERNELBASE.dll`, `win32u.dll`, …) as injected. Root cause:
`NtQueryVirtualMemory(MemoryMappedFilenameInformation)` returned a `\??\C:\…`
DOS-device path instead of the NT device path `\Device\HarddiskVolumeN\…` that
`GetMappedFileName` actually returns; al-khaser converts the mapped name back to a
drive letter via the device map to match the loader list, and `\??\C:` doesn't
convert. Fixed by routing through `DosPathToNtDevicePath` (the same
`\Device\HarddiskVolume1` formatter the F4 `ProcessImageFileName`/`QueryDosDevice`
work uses). All diagnostic instrumentation for this pass was reverted (tree stays
clean).

### F2 — Emulation throughput

**Measured, not assumed (this pass).** Bounding the scheduler and timing it
(silent, so no trace I/O) shows Brovan's **raw per-instruction throughput is
healthy**: ~4.3M insn/s early, ~6.3M insn/s steady-state; a full detection pass
(~24M instructions) that lands on the scheduler's clean-bail path completes in
**~4 s**. Traced (no `-s`) is ~2.9M insn/s — a ~1.6× penalty from the
per-instruction CFT/ENTRY module/section lookups, **not** console I/O (only ~300
lines print per 2.4M instructions). So "raw speed" is not the problem.

**Where the wall-time actually goes.** The >240 s "hang" is not slow
instructions — it is a very large *number* of instructions, from two sources,
both outside pure throughput:

- **F1 spin.** On the livelocked interleaving a thread free-runs `RtlpBackoff`
  (`rdtsc`+`pause`) forever; at ~5M insn/s a 2-minute run is ~500M no-progress
  instructions. The biggest wall-time lever is a scheduler spin/livelock
  detector (see F1), not per-instruction micro-optimisation.
- **F3 NLS storm (now fixed, `b205488`).** `kernelbase` re-opened
  `sortdefault.nls` ≈4684×/run (+ ~40 section ops). The re-opens were a
  **symptom** of the F3 bug, not an independent cost: kernelbase's per-locale
  sort load failed every compare (the sort registry never populated because the
  `sortdefault.nls` open returned `INVALID_HANDLE_VALUE` — see F3), so it
  re-attempted the whole open→map→parse each time. `b205488` makes the open (and
  thus the load) succeed **once**; the storm is gone — better than caching it.

**Per-instruction ceiling (for reference).** Disabling both always-on
`UC_HOOK_CODE(1,0)` hooks raised the CPU-bound phase from 4.3M→7.2M insn/s
(~32 %): `InstructionHandler` ~24 % (of which the `IRETQ` `uc_mem_read` was
~11 %, now fixed in `bc151f0`), the `PebLdrTracker.OnBlock` LDR-sync poll ~4 %,
the rest being the irreducible callout. The `IRETQ` read was the one clean,
safe, semantics-preserving slice and is landed. The remaining per-instruction
cost is hard to reclaim without risk: the hook must stay per-instruction for the
TSC counter (anti-timing realism — `_timestampCounter += 3` per instruction,
consumed by tight `rdtsc`-delta probes), and `OnBlock`'s 4 % would need a new
`UC_HOOK_BLOCK` path plumbed through the backend abstraction (Unicorn + KVM) for
little gain. **Conclusion: per-instruction throughput is near its safe ceiling;
F3's `sortdefault.nls` re-open storm is now fixed (`b205488`), so the last big
remaining throughput lever is F1 (scheduler spin detection), not more
micro-optimisation here.**

**Where the DLL-injection probes' time actually goes (sampling profiler, this
pass).** To test whether the slow `Walking process memory` probes hide a
reducible O(N) Brovan hotspot, a sampling profiler (bucket RIP at 64-byte
granularity every 4096 instructions, dump hottest buckets) was run over the
probe. The cost is **distributed across genuine guest work, with no single
Brovan-side hotspot**:

- al-khaser's **own string-comparison loops** (`al-khaser_x64.exe+0xCB00..0xCE00`,
  a `jne`-chain comparing bytes) — the plurality of samples.
- kernelbase **`GetStringTypeExW`** (`+0x22D80..0x22E80`, ~1160 samples) —
  character classification behind case-insensitive comparison. This is the *cost
  of the F3 fix succeeding*: the injected-library checks now actually run the real
  NLS collation (they used to error out with `-2`), and al-khaser does many such
  comparisons (each module path against the loader list).
- ntdll **`RtlVirtualUnwind`/`RtlLookupFunctionEntry`** (`+0x322C0..0x32FC0`) +
  **`RtlNtStatusToDosError`** (`+0x50840`) — x64 exception unwinding + status
  translation, i.e. the sample's `__try/__except`-wrapped probing dispatching real
  exceptions.

None of these is a Brovan inefficiency to optimise away — they are the guest
executing a heavy anti-analysis suite (string matching + NLS collation +
exception dispatch) faithfully, instruction by instruction. So F2 on these probes
is **irreducible at the per-instruction level**; a real speedup would need a
coarser execution strategy (block-level JIT / native exception fast-path), which
is a large architectural change, not a hotspot fix. This confirms the
near-ceiling conclusion above. All profiler instrumentation was reverted.

### F3 — Injected-library false positive (NLS collation) — **FIXED (`b205488`)**

Fixed this pass. The root cause was **not** in the guest NLS code — the earlier
"trace the sort version inside `SortGetHandle`" recommendation was a red
herring. kernelbase's `CompareStringW` / `StrCmpNIW` / `StrCmpIW` returned a
constant error because `kernel32!SortGetHandle` could not **open**
`C:\Windows\Globalization\Sorting\sortdefault.nls`. That open failed in
Brovan's own read-path resolver, which extracted the file leaf with
`Path.GetFileName` — which splits on `/` on Linux, so on a backslash guest path
it returned the whole string as the "leaf" and missed the WindowsLibs index.
Fixed with a separator-agnostic `WindowsLeafName` helper. The full write-up —
including the version-gate arithmetic that rules out the file-swap theory and
the before/after compare-return evidence (constant `-2`/`0` error → correct
`0`/`-1`/`CSTR_*` results) — is in the landed **`b205488`** entry under *Past
corrections* above.

### F5 — x86 / WOW64 unsupported

**Symptom:** `al-khaser_x86.exe` does not run.

**Cause:** Brovan implements very few x86 syscalls and no WOW64 thunking. Out of
scope for the x64 work above; a separate, large effort.

## Investigation method (for the next pass)

1. Run with the trace on (no `-s`), pipe through `grep --line-buffered` for the
   markers of interest, cut the prompt spam with `printf 'start\nexit\n'`.
2. A terminus with a status code (`0xC0000005`, `0xC0000139`, …) is a loader /
   CPU fault; a `terminate`/`__fastfail` is an uncaught C++ exception. Both are
   worth one targeted diagnostic before theorising.
3. Instrument the exact chokepoint (`NtCreateFile`, `NtReadVirtualMemory`,
   `HandleInvalidMemory`, `RunMlfqScheduler`) via `TriggerEventMessage(...,
   LogFlags.General)`; capture the faulting IP + operands.
4. Disassemble the guest binary (`objdump -d -M intel --start-address ...
   --stop-address ...`) and the guest ntdll (ImageBase `0x180000000`) at the
   faulting RIP; PE thunks (`jmp [__imp_...]`) will mislead a naive
   return-address read, so resolve the real call site / export.
5. Fix the root cause in the smallest generic way; re-run and confirm the
   terminus moved. Each fix here revealed the next frontier — expect the same.
