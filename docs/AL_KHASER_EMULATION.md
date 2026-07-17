# al-khaser emulation — corrections log

Running the [al-khaser](https://github.com/ayoubfaouzi/al-khaser) anti-VM /
anti-debug / anti-analysis suite through Brovan on a **non-Windows host** (Linux
x86-64) surfaced a chain of loader, filesystem, syscall and threading gaps.
This file records every correction that has landed, and every frontier that has
been diagnosed but not yet fixed, so the work can be picked up without
re-deriving the analysis.

Scope: **al-khaser x64** (fully running its detection suite) and **al-khaser x86 /
WOW64** (foundation landed — the 32-bit ntdll loader now runs deep into process
init; see Frontier F5 for the full WOW64 model, landed primitives, and the current
loader-TLS frontier).

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

**Invalid-handle wait terminus fixed — `NtWaitForMultipleObjects` now validates
handles (deep-run ceiling 88 → 95 `GOOD`).** After the rescued-page memory fix
lifted the earlier `0xC0000005` ceiling, a fraction of runs reached a **new
silent terminus** deep in the `Generic Sandbox/VM Detection` section: the main
thread parked on `NtWaitForMultipleObjects` returning `STATUS_PENDING` forever
(~130 M instructions, 88 `GOOD`), so the scheduler ran out of runnable threads
and returned. Instrumenting the block point showed the wait array held handles
that Brovan never allocated — a constant `0x4` (below the `0x40` handle base) plus
a run-varying second slot (`0x7C`/`0x7E`, sometimes resolving to an unrelated ETW
registration) — sourced by the **real `setupapi.dll`/`devobj.dll` device-
enumeration path** that `al-khaser`'s `SetupDiGetClassDevsW` VM-hardware probe
drives. Root cause: `NtWaitForMultipleObjects` did **not** validate its handles —
an unknown handle was silently treated as "never satisfiable" and the wait parked
indefinitely. Real Windows references every object by handle *before* waiting and
fails the whole call with `STATUS_INVALID_HANDLE` if any is invalid (it never
blocks); `NtWaitForSingleObject` already did exactly this for its single handle.
The one-file fix ports that check to the multi-object path (every waitable object
lives in the handle table, so a null lookup is a genuinely invalid handle — both
`CanSatisfyWaitHandle` and `WindowsGuest.IsHandleSignaled` agree). With it, the
device-enumeration wait returns `STATUS_INVALID_HANDLE` once (no retry spin —
`NtWaitForMultipleObjects` fires exactly twice per run, the legitimate first wait
unchanged), `SetupDiGetClassDevsW` takes its error path, and the run continues:
the deepest interleavings now print **95 `GOOD` / 1 `BAD`** (up from 88/0) before
hitting the pre-existing `0xC0000005` memory-coherence terminus further along. The
new `1 BAD` is `al-khaser`'s *"process loaded modules contains: dbghelp.dll"*
check. **RESOLVED (and it was never SEH/WER — see
`docs/SEH_WER_DISPATCH_INVESTIGATION.md`):** runtime tracing proved `faultrep.dll`
(+ its static import `dbghelp.dll`) was dragged in **at load time by a bogus
`ApiSetOverrideMap` entry** (`ext-ms-win-kernel32-errorhandling-l1-1-0 →
faultrep.dll`), with **no exception involved** — kernelbase statically imports that
error-handling contract, and the override mis-resolved it to the fault-*reporting*
DLL. Fix: the contract now resolves to `KERNELBASE` (matching real Windows), so
faultrep ships on disk (file-existence probe passes) but is never loaded and dbghelp
never enters the LDR (`BAD → GOOD`). The stop-the-spurious-load-don't-mask-it
requirement below was met at the source. The earlier
GS/stack-cookie `__fastfail` and null-read `wcslen` termini (both ~48 `GOOD`,
run-specific pages in the same `0x100120000` allocation family) are the same open
memory-model coherence question.

**Decommit-rescue now restores real content, not zero (removes the `0xC0000005`
deep-run cap; full-suite completion becomes reachable).** The rescue path
(`TryRescueDecommittedRead`) re-mapped a decommitted heap page on a fault but
handed back a **fresh zero page** — it restored the page's protection, not its
bytes. The rescue's own premise is that the decommit is a Brovan interleaving
artefact (real Windows never reaches the decommitted state inside the probe's
window), which means the page's content is still logically valid and must come
back intact; zeroing it handed the guest `0` where a live pointer / allocation
size / stack cookie once sat. Over a deep run this accumulated and was the source
of the run-specific NULL-derefs and `0xC0000005` faults in the memory-walk probes
that **hard-capped every baseline interleaving at 95 `GOOD`** (no baseline run has
ever exceeded it). `DecommitMemory` now snapshots each page's bytes before
unmapping (parallel-keyed `DecommittedContent`, dropped on rescue-restore and on
reclaim/commit), and `TryRescueDecommittedRead` writes them back after re-mapping.
The write uses the backend path so it bypasses guest protection, and a legitimate
decommit→commit→read still gets fresh zeros (the commit reclaim drops the saved
content first) — so no observable Windows semantics change. Effect is
**non-deterministic** (which pages get decommitted / rescued / re-read varies
run-to-run, so the corruption — and thus the fix's benefit — is hit-or-miss per
run): across batches the early-terminus rate drops and, decisively, some
interleavings now run al-khaser's **entire suite to completion** — a clean
`GetMessageW` / `NtUserGetMessage` message-loop terminus at **247 `GOOD`** —
which the zero-rescue baseline could categorically never reach. No run regressed
(worst case is the unchanged ~48/95 terminus). The residual ~48 GS-`__fastfail` is
**stack** corruption the heap rescue never touches and is unaffected — the next
memory-coherence frontier. **[SUPERSEDED — see "RESOLVED" below: the residual-48
terminus was NOT stack corruption but a host-pointer bookkeeping desync on partial
unmap; fixed, 48 → 248 GOOD.]**

**Guest-visible non-determinism pinned (reproducibility + removed per-run tells).**
Two runs of the *same* sample diverged (e.g. 130.6 M vs 132.1 M instructions), and
several synthetic-identity values changed every run. The `EmulatedTickCount64`
delta already advanced purely by instruction count, but the surrounding sources
leaked host state: the system-time BASE was `DateTime.UtcNow`; `QueryPerformance
Counter` returned the host `Stopwatch.GetTimestamp()` (non-deterministic AND a
stealth tell — a QPC-vs-RDTSC/GetTickCount timing check saw the huge, variable
emulation cost instead of a coherent virtual delta); the volume GUID was
`Guid.NewGuid()`; PIDs and the KUSER `SharedUserData->Cookie` came from an unseeded
`Random` / crypto RNG; and the guest username was a **random-length** string
(5–11 chars) whose length rippled into every path/env/compare, jittering the
instruction stream. Fix: one deterministic per-sample seed (`BinaryEmulator.
DeterministicSeed`, FNV-1a over the image bytes) drives a single shared
`SeededRandom` and the clock base; QPC now derives from the emulated TSC
(invariant-TSC model, 10 MHz); the internal LDR-refresh `Pump` throttles by
emulated time, not host `Stopwatch`; and `NtQueryAttributesFile` file times use
the emulated clock. Crypto RNG (`BCryptGenRandom` / `RtlGenRandom`) stays genuinely
random. Result: run-to-run variance collapses from ~12 %+ with 48/95/247 depth
swings to a **stable verdict** (+~0.4 % residual instruction jitter). **Trade-off,
accepted deliberately:** pinning timing/identity/layout also pins the still-open
memory-coherence frontier, so al-khaser now hits the 48-`GOOD` terminus
*consistently* instead of reaching ~95 on lucky interleavings — reproducible-48 is
the honest state and a better base for fixing the corruption than flaky-48/95.
Recovering depth deterministically is now purely a matter of fixing that heap/stack
corruption. A few niche GUIDs (AFD socket paths, RPC context ids) and the USN-journal
timestamp are still `Guid.NewGuid()`/`DateTime.UtcNow`; al-khaser does not exercise
them, so they are the residual determinism gap.

---

## RESOLVED — the "corruption" was a host-pointer bookkeeping desync, not a heap/stack timing race. 48 → 248 GOOD.

**Everything below this line in the older "memory-coherence frontier" / "not fixable
by a Brovan-side patch" analysis is SUPERSEDED.** Instruction-level instrumentation
(env-gated, since reverted) proved the earlier root-cause attribution wrong on every
point: the decommit-content **rescue path fires 0×** in the terminating run, and the
fault is **not** a GS-`__fastfail` stack-cookie smash — it is a plain NULL-read
`0xC0000005` at al-khaser's hidden-module MZ-probe (`cmp byte [rax],0x4D`, `rax=0`,
IP `0x14000CA73`). At the fault, the C# host-pointer view (`ReadMemoryULong`) returned
the correct value while the guest CPU's own read (`uc_mem_read` path) returned `0` — a
**backend-vs-C# mapping desync**, not a TLB/cache staleness (an explicit
`UC_CTL_TLB_FLUSH` + TB-cache removal did **not** clear it).

**Real root cause.** `Unicorn.UnmapMemory` reconciled the C# `_mappedRegions` view
(consulted by `TryGetHostPointer` for every emulated read/write) with the backend
**only on an exact `(Address,Size)` match**. The guest ntdll segment heap constantly
issues *sub-range* `NtFreeVirtualMemory(MEM_DECOMMIT)` on parts of a larger arena
(`AllocationBase 0x100120000`). `uc_mem_unmap` split its own mapping correctly, but the
stale full-size C# entry survived and kept aliasing the *old* host buffer; a later
`MapMemory` re-backed that VA with a **new** buffer in Unicorn. `TryGetHostPointer`
then resolved the VA to the stale buffer, so emulated `NtQueryVirtualMemory` wrote the
`MEMORY_BASIC_INFORMATION` into a buffer the guest never reads → a page-straddling
MBI node's `BaseAddress` read as `0` → `cmp [0]` → AV. (This is why only straddling
nodes faulted, and why the earlier "stack corruption" / heap-decommit-timing framing
never reconciled with the evidence.)

**Fix** (`Unicorn.cs`, `UnmapMemory` only, all guests — commit *Fix host-pointer desync
on partial unmap*): `ReconcileUnmap` splits every `_mappedRegions` entry overlapping the
unmapped range into its surviving left/right halves, mirroring Unicorn's own
`split_region` (the right half's `Ptr` shifts by `overlapEnd - rStart` so it stays
aliased into the same host buffer at the correct offset). A new `MappedRegion.AllocBase`
records the real `AlignedAlloc` base; the buffer is deferred-freed only once no surviving
region references it (also closing a latent free-of-wrong-pointer). No masking, no ntdll
patching, no sample-specific tuning, no budget change — a pure backend-invariant
correctness fix, so the rejected-fix table below no longer applies (none of those levers
were needed).

**Result** (deterministic across runs): al-khaser advances **48 → 248 GOOD / 7 BAD**,
past the entire anti-VM suite (VirtualBox/VMware/Parallels/Hyper-V) to its own
**Timing-attacks** long-sleep section (the new terminus is the sample's deliberate
600 s delay, not a crash). The **7 BAD** are newly-reachable, orthogonal anti-emulation
stealth gaps (time-acceleration, WMI CPU-fan, ACPI-table-string probes) never reached
before because the run died at probe 48 — a fresh, separate work item, not a regression.
Regression guard: svchost/services/lsass/spoolsv/rundll32/csrss/explorer all still exit
clean. The heap-decommit-content rescue (`DecommittedContent` / `TryRescueDecommittedRead`)
is retained but was **not** what unblocked this terminus.

**Determinism residuals now also closed.** The "niche GUIDs (AFD/RPC) + USN timestamp"
gap noted just above, plus a `ProcessCookie` still seeded from `Random.Shared` (it feeds
the guest CRT stack-cookie derivation), are all now routed through the per-sample
`SeededRandom` / emulated clock. Crypto RNG (`BCryptGenRandom` / Ksec / Cng) stays
genuinely random by design.

### Anti-VM probe hardening after the desync fix — 48 → 251 GOOD / 4 BAD

Clearing the hidden-modules terminus exposed the rest of al-khaser's suite. Fixed since:

- **ACPI firmware tables** (`NtQuerySystemInformation` `SystemFirmwareTableInformation`,
  previously unimplemented): `EnumSystemFirmwareTables`/`GetSystemFirmwareTable('ACPI')`
  now return a bare-metal table set (FACP/APIC/HPET/MCFG/SSDT/BGRT/WSMT, no `WAET`, no
  fabricated tables — absent signatures fail with `STATUS_NOT_FOUND`). Flips the
  VirtualBox + VMware "Checking ACPI tables" probes to GOOD.
- **`GetTickCount` returned 0 for all guests** — `KUSER_SHARED_DATA.TickCountMultiplier`
  (offset 0x004) was never written, so `(TickCount.Low * 0) >> 24 == 0`. Set to the
  standard `0x0FA00000`; GetTickCount now tracks `EmulatedTickCount64` ms. Flips
  al-khaser's `accelerated_sleep` ("Check if time has been accelerated") to GOOD, and is
  a general correctness fix for any GetTickCount-based timing.

**Residual 4 BAD — honestly left:**
- **"Checking ACPI table strings" + QEMU "Checking ACPI tables"** both route through
  al-khaser's `firmware_ACPI()`, which returns detected unless EVERY enumerated ACPI
  table contains all five of `PNP0000`/`PNP0C0C`/`PNP0C0E`/`PNP0C14`/`PNP0D80`. No real
  bare-metal firmware satisfies that (FADT/MADT/HPET carry no PnP device IDs), so this
  al-khaser check false-positives on real hardware too. Passing it would require embedding
  fake PnP strings in every synthetic table (unrealistic forgery / over-fit to one tool),
  so it's left BAD per the "return realistic values, don't over-fit" discipline.
- **"Checking CPU fan using WMI"** (`SELECT * FROM Win32_Fan`, detected when 0 instances)
  and **"VM Driver Services"** (`OpenSCManager` returns NULL) each need a subsystem Brovan
  doesn't have: a WMI query-interception provider that synthesizes a `Win32_Fan` instance,
  and a `svcctl` RPC endpoint (`ROpenSCManagerW` + service enumeration). Both are scoped
  follow-ups, not stub gaps.

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
syscalls — a different subsystem). Six are now implemented — the four below plus
`NtGetWriteWatch` (0xFB) / `NtResetWriteWatch` (0x179), covered in the write-watch
entry that follows — each auto-registering via the `IWinSyscall` generator (the SSN
is read from the shipped ntdll, so it tracks the build):

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

**Landed (the "needs a feature" pair, done right).** `NtGetWriteWatch` (0xFB) /
`NtResetWriteWatch` (0x179) back al-khaser's four write-watch checks (buffer-only /
API-calls / IsDebuggerPresent / code-write), which detect an emulator when the
reported dirty-page set doesn't match what was actually written. Implemented as a
**genuinely opt-in** feature (`System/.../WriteWatchManager.cs`): a region allocated
with `MEM_WRITE_WATCH` (0x00200000) gets a **ranged** Unicorn write hook scoped to
just that region, so a program that never uses the feature pays **zero** cost (the
backend filters the hook range before any managed callback runs — no global
per-write hook, sidestepping the F2 concern entirely). The design is correct by a
Unicorn property: only guest STORE instructions trigger the write hook, while
host-side stub writes go through `uc_mem_write` (which bypasses hooks) — so a probe
that hands the buffer to a *failing* API and expects a **zero** hit-count gets it
(the API never stored to the buffer), while a real `buffer[0]=x` store yields
exactly one dirty page. `NtGetWriteWatch` returns the pages ascending + granularity
0x1000 and honours `WRITE_WATCH_FLAG_RESET`; `NtResetWriteWatch` clears the set (the
code-write probe writes generated code into the buffer, resets, runs it, then
expects zero). Registered on the MEM_WRITE_WATCH alloc, unregistered (hook removed)
on MEM_RELEASE. Verdict unchanged at **48 GOOD / 0 BAD** — the four probes stay GOOD
and the syscalls are now exercised for real (4× `NtGetWriteWatch → STATUS_SUCCESS`,
1× `NtResetWriteWatch → STATUS_SUCCESS`, plus one intentional `INVALID_PARAMETER`
for the API-calls probe's non-watch query), stable across runs, instruction count
identical to baseline (no throughput regression). This closes the write-watch
anti-emulation class faithfully rather than with the previous always-fail
`STATUS_NOT_SUPPORTED`.

**Landed (fidelity pass on the still-noisy return paths).** Every previously
`STATUS_NOT_SUPPORTED` syscall / info-class the run touched was audited against
what real Windows returns from an unprivileged token, and each replaced with the
correct answer. Verdict unchanged at **48 GOOD / 0 BAD** (stable across 4 runs);
the residual noise dropped from 12 unimplemented markers per run to 4 (all in
paths where no clean answer exists: `0xC8 NtCreateUserProcess` fired by the CRT
terminus spawning WerFault, `0x1037` / `0x105D` `win32u` GUI syscalls, one
`ProcessTelemetryCoverage` init call).

- **`NtQueryInformationAtom` (0x147)** — implemented. Integer atoms
  (`>= 0xC000`) round-trip through `ATOM_BASIC_INFORMATION` with the canonical
  `"#N"` name; string-atom queries — the al-khaser `GlobalGetAtomName(bogus)`
  probe uses this shape — return `STATUS_INVALID_HANDLE` (matches real Windows
  when the atom isn't in the process's atom table), so `GlobalGetAtomName`
  fails without writing the OUT buffer. Previously the `NOT_SUPPORTED` reply
  worked only by kernel32's LastError propagation.
- **`NtSetSystemInformation` (0x1AA)** — implemented. Kernel-mode / TCB-privileged
  surface; from a non-elevated user process real Windows returns
  `STATUS_PRIVILEGE_NOT_HELD` for every information class (the callable-from-userland
  carve-outs still need `SeTcbPrivilege`). Returning that instead of NOT_SUPPORTED
  matches the honest usermode answer.
- **`NtQueryInformationProcess(ProcessDebugFlags = 0x1F)`** — implemented. Real
  Windows returns `NoDebugInherit = 1` for a non-debugged process; al-khaser's
  probe checks `Status == SUCCESS && buffer == 0` for BAD, so `SUCCESS + 1` is
  both the honest "no debugger" answer and the value that keeps the probe GOOD.
  The old NOT_SUPPORTED reply worked only because the probe treats a failed
  call as GOOD too.
- **`NtQueryInformationProcess(ProcessDefaultHardErrorMode = 0x0C)`** — implemented.
  Called by ntdll's process-init code path; `SUCCESS + 0` (SEM_ flags all clear,
  default critical-error handling) matches real Windows.

**Still deferred.** `NtCreateUserProcess` (0xC8) fires once from the CRT terminus
spawning WerFault after the walker AV — the syscall is a full process-creation
surface (14 args, PS_ATTRIBUTES) with no honest usermode payoff to model on this
sample, and no probe hangs on it. `NtQueryInformationProcess(0x56 =
ProcessTelemetryCoverage)` is a WIP telemetry class ntdll may or may not expose
depending on the build; keeping it NOT_SUPPORTED is the honest answer. The
`win32u` GUI syscalls (`0x1037`, `0x105D`) remain out of scope for the ntdll pass.

**Verified with a corrected bundle (SortDefault.nls + WUDFPlatform.dll + faultrep.dll
shipped).** Re-exporting with the fixed `Export-BrovanDeps.ps1` and re-running
confirms the deps analysis end-to-end:

- **Injected-library FP eliminated** — with `SortDefault.nls` present the collation
  works, and the 397 `[!] Injected library` lines / the whole class of System32-module
  false positives drop to **0**. `WUDFPlatform.dll` now loads and al-khaser's
  `WudfIs{Any,Kernel,User}DebuggerPresent` resolve and execute (were NULL before).
- **Verdict 44 GOOD / 4 BAD** (from 38/10 at the start of this work). The four
  remaining `BAD` probes — `NtSetInformationThread(ThreadHideFromDebugger)`, `Int
  0x2D`, `SeDebugPrivilege`, `NtYieldExecution` — are landed as fixes in the
  follow-up pass below (verdict `48 GOOD / 0 BAD`).
- **New terminus surfaced, non-deterministic.** With the FP-storm gone the flow is
  shorter and different; one interleaving reaches MSVC's `__report_gsfailure`
  (`__fastfail(FAST_FAIL_STACK_COOKIE_CHECK_FAILURE)` / `int 0x29`, `0xC0000409`) at
  ~47 M inside the now-correct module-scan path, another runs past it to ~73 M
  hitting a `0xC0000005` in the same path. Investigated this pass (below); both
  termini share one root cause. The livelock watchdog stays silent throughout.

### Landed later — soft-rescue on decommitted-read closes the walker terminus

The intrinsic-timing analysis below stayed correct, but the terminus itself is now
closable with a **fault-driven rescue** that leaves observable Windows semantics
intact (VirtualQuery still reports MEM_RESERVE for the affected pages). Design:

- `DecommitMemory` still unmaps in the backend as before AND records each
  page it drops into `DecommittedPages` (per-emulation `HashSet<ulong>`) along
  with the region's pre-decommit protection in `DecommittedProtection`.
- On any read/write/fetch fault the guest layer's new
  `TryRescueDecommittedMemory` runs before the fault dispatches: if the page
  is in the set, it is re-mapped in the backend with its original protection
  and removed from the set. `InvalidMemoryHandler` returns `true`; the guest
  access retries and succeeds — the walker completes and the process runs on
  to whatever probe comes next.
- `CommitMemory` and `ReleaseMemory` call `ReclaimRescuedPages` which unmaps
  any earlier-rescued page in the target range so the caller's own MapMemory
  (COMMIT) or UnmapMemory (RELEASE) has clean ground; freshly-released
  pages correctly go MEM_FREE and any subsequent access there faults.
- Only the Windows guest wires the rescue — Linux / Generic default to false
  so their semantics are unchanged.

**Observable effect**: the terminus documented below (0xC0000005 at
`0x14000CA73`) no longer happens on the "walker snapshotted + heap decommitted"
class. Al-khaser's `Walking process memory for hidden modules` probe completes
(`-> 0`) and the run continues into the **AntiDumping / SystemInfo / AntiVM /
HumanInteraction** categories that were previously blocked. New high-water mark:
**92 GOOD / 4 BAD** across ~124 M instructions on the deeper interleaving
(steady state per run is non-deterministic — some runs still terminate earlier
on other AVs in downstream probes, but the walker terminus itself no longer
fires deterministically). The 4 new BADs are all real fidelity gaps we haven't
patched yet, not accidental passes:

- **`Checking if process loaded modules contains: dbghelp.dll`** — **RESOLVED
  (not SEH/WER).** `faultrep.dll` (+ static import `dbghelp.dll`) was pulled in at
  **load time** by a bogus `ApiSetOverrideMap` entry
  (`ext-ms-win-kernel32-errorhandling-l1-1-0 → faultrep.dll`), not by any WER path
  — runtime tracing recorded zero exceptions before the map. That error-handling
  contract (kernelbase statically imports it) now resolves to `KERNELBASE`, matching
  real Windows; faultrep ships on disk but stays unloaded. See
  `docs/SEH_WER_DISPATCH_INVESTIGATION.md`.
- ~~**`Checking mouse movement`**~~ — **fixed**, see *Landed later — cursor
  movement fidelity* below.
- ~~**`Checking memory space using GlobalMemoryStatusEx`**~~ — **fixed**, see
  *Landed later — RAM + disk size fidelity* below.
- ~~**`Checking disk size using GetDiskFreeSpaceEx`**~~ — **fixed**, see
  *Landed later — RAM + disk size fidelity* below.

**Fingerprint discipline**: the only Windows-observable divergence from the
rescue path is that a guest read of a page whose VirtualQuery reports
MEM_RESERVE (having been decommitted) returns stale bytes instead of raising
STATUS_ACCESS_VIOLATION. No al-khaser variant, pafish, or VMAware probe tests
this specific "read-decommitted-expect-AV" shape (each of them walks memory
through VirtualQuery + read *believing* the region is committed, and their code
has no SEH around the byte read — the AV is a Brovan-specific timing artefact,
not a probe target). The alternative — the deterministic `0xC0000005` terminus
we had before this change — was strictly more fingerprintable (100 % crash on
the "hidden modules" probe on every run).

### Landed later — RAM + disk size fidelity (both size probes → GOOD)

With the walker terminus unblocked, al-khaser reaches its `SystemInfo`-category
size probes, which had surfaced two `BAD`s. Both were honest fidelity gaps, both
now fixed and confirmed `GOOD` end-to-end on a run that reaches them (`memory
space using GlobalMemoryStatusEx → GOOD`, `disk size using GetDiskFreeSpaceEx →
GOOD`, alongside the already-passing `hard disk size using WMI` /
`DeviceIoControl`).

- **Disk size (`GetDiskFreeSpaceEx`)** — `WindowsStorageDeviceSupport` reported a
  64 GB volume (`TotalClusters = 0x01000000` × 4 KiB/cluster). al-khaser's disk
  probes fail any volume under a 60–128 GB floor, so 64 GB read as a VM. Bumped
  the single `TotalClusters` SSOT to `0x08000000` → a realistic 512 GB SSD, which
  propagates coherently to every derived surface (drive geometry, NTFS volume
  data, disk extents, `FileFsSizeInformation`). Also added
  `FileFsFullSizeInformation` (class 7) to `NtQueryVolumeInformationFile` so the
  modern `GetDiskFreeSpaceEx` takes its primary query path instead of the
  error-fallback to `FileFsSizeInformation` (class 3).

- **RAM (`GlobalMemoryStatusEx`)** — root cause was NOT a wrong value but an
  unhandled class: modern `kernelbase!GlobalMemoryStatusEx` sources the *entire*
  `MEMORYSTATUSEX` from a single `NtQuerySystemInformation(SystemMemoryUsageInformation
  = 0xB6)` call (verified from the syscall trace — it makes no other query and
  does **not** consult `SystemBasicInformation`). Brovan returned
  `STATUS_NOT_SUPPORTED`, so the function returned with the buffer unfilled
  (`ullTotalPhys == 0`), reading as a sub-2 GB VM. Implemented class `0xB6`
  returning the full 0x38-byte `SYSTEM_MEMORY_USAGE_INFORMATION` (layout confirmed
  against `ntdiff/headers` extracts, identical 1607→22H2, and multiple phnt
  copies) on both the plain and `Ex` syscall surfaces.

- **New RAM SSOT** — the physical-page count (`0x200000` = 8 GiB) had been
  duplicated inline in `SystemBasicInformation` and its `Ex` twin. Extracted to
  `WindowsMemorySupport` (mirroring the `WindowsStorageDeviceSupport` idiom) so
  every RAM-reporting surface reads one coherent 8 GiB machine — a sample that
  cross-checks total RAM across `SystemBasicInformation` and
  `SystemMemoryUsageInformation` sees agreeing answers (realism rule #1). The
  five commitment figures are internally consistent (Available < Total, Committed
  < CommitLimit, Peak ∈ [Committed, CommitLimit]).

Both fixes are pure fidelity — realistic, deterministic, SSOT-derived — with no
sample-specific values (rules #4, #6).

### Landed later — cursor movement fidelity (`mouse movement` → GOOD)

al-khaser's human-presence probe samples the cursor twice across a `Sleep` and
flags an unmoving cursor as a sandbox. `user32!GetCursorPos` faulted through to
`STATUS_NOT_SUPPORTED`, so the caller's `POINT` stayed `(0,0)` on both reads.

The routing was not obvious. `GetCursorPos` issues win32u syscall `0x102A`, but
that SSN is **not** `NtUserGetCursorPos` (which this build's win32u does not even
export) — disassembling the bundled `user32!GetCursorPos` shows
`mov edx,1; lea r8d,[rdx+0x7e]; jmp NtUserCallTwoParam`, i.e. it tail-calls the
`NtUserCallTwoParam(lpPoint, 1, 0x7F)` multiplexer (`GetPhysicalCursorPos` routes
identically). Implemented `NtUserCallTwoParam`: for code `0x7F` it writes a
screen-space `POINT` and returns TRUE; every other code returns
`WinUnimplemented` (STATUS_NOT_SUPPORTED), preserving prior behaviour so
registering the handler regresses nothing.

The position is a smooth Lissajous (two coprime-ish triangle-wave periods, ~0.3
px/ms, bounded well inside 1920×1080) driven by the guest virtual clock
(`EmulatedTickCount64`, which `Sleep`/`NtDelayExecution` advances). Two reads
separated by any nonzero delay therefore differ — realistic human movement, not
fabricated per-call jitter (rule #4). Verified `GOOD` end-to-end (the syscall now
logs `NtUserCallTwoParam (0x102A) → STATUS_SUCCESS`, `mouse movement → GOOD`).

**Generator caveat learned here**: the win32k syscall registry is
source-generated from the handler class names. A compile *error* in a
just-added handler poisons the incremental generator cache, so the next
*successful* incremental build silently ships a registry without the new class
(the syscall stays "unimplemented" at runtime with no build error). Rebuild
`--no-incremental` after adding a syscall handler, and confirm the class appears
in `obj/**/WinRegistry.g.cs`.

Remaining `SystemInfo`-adjacent BAD: the `dbghelp.dll` loader-list probe is now
RESOLVED (bogus apiset override → faultrep, fixed to resolve to KERNELBASE; described
above), leaving no open `SystemInfo`-adjacent BAD.

### Traced this pass — the "hidden modules" AV is an intrinsic timing race

> **[SUPERSEDED by the "RESOLVED" section above.]** This pass concluded the AV was an
> intrinsic segment-heap decommit *timing race* that was "not fixable by a Brovan-side
> patch." Later instruction-level instrumentation disproved that: the fault is a
> host-pointer bookkeeping desync in `UnmapMemory` (stale `_mappedRegions` entry after a
> partial `uc_mem_unmap`), fixed generically via `ReconcileUnmap`. The decommit *does*
> happen mid-walk, but a correct C#-vs-Unicorn mapping mirror makes the guest read the
> right buffer, so the walk no longer faults (48 → 248 GOOD). The rejected-fix reasoning
> and the `RtlpHeapReservedBytes` "deferred direction" below were both moot — the bug was
> not in the heap model at all. Kept for the trace detail (fault site, ntdll RVAs).

Instrumented (env-gated `BROVAN_QVMDBG`, reverted) to bracket the fault site
`0x14000CA73: cmp BYTE [rax], 0x4d` in al-khaser's hidden-module scanner
(`fn 0x14000C9D6-0x14000CBDE`). The mechanism, verified against 10+ runs:

1. **Al-khaser snapshots MBIs into a heap-allocated vector**
   (`fn 0x140017230`: `HeapAlloc(48)` per MBI, `VirtualQuery(addr, mbi)`, push
   into `std::vector`, advance by `mbi.RegionSize`). ~25 000 `NtQueryVirtualMemory`
   calls in a **1.7 M-instruction window** ending at insn ~47 M. Every reply
   is a snapshot of the region topology at that instant.

2. **Al-khaser then walks the snapshot linearly** in the enclosing function
   at `0x14000C9D6`, calling `GetModuleHandleExW(FROM_ADDRESS, page)` per page
   and — if the page is COMMIT+readable per the *snapshotted* MBI — reading
   `[page]` to check for the `MZ` magic. Each iteration is ~1 000 instructions
   (module-handle lookup + PEB LDR walk + string ops); the whole walk is
   ~25 M instructions and covers insn ~47 M → ~72 M.

3. **During that walk, the emulated ntdll segment heap calls
   `NtFreeVirtualMemory(MEM_DECOMMIT)`** ~50 times, all from the same site
   (`ntdll+0x20957`, a heap-manager decommit helper called via
   `ntdll+0x9AF4 = NtFreeVirtualMemory`). The decommit ranges are subranges
   of the same `AllocationBase=0x100120000` heap arena al-khaser is walking.

4. **The snapshotted MBI at page P still says `COMMIT+RW`** (from step 1) but
   at read time (step 2) the page has been **decommitted** (step 3). The
   `cmp [rax], 0x4d` then raises `EXCEPTION_ACCESS_VIOLATION`.

5. **The fault is not caught by al-khaser code.** `fn 0x14000C9D6-0x14000CBDE`'s
   unwind info has `UNW_FLAG_CHAININFO` (no local scope table); the SEH
   walker chains up, `__C_specific_handler` is invoked from thunk `0x140018BA6`,
   returns `ExceptionContinueSearch`, and the exception reaches `main()`'s CRT
   top-level filter `_seh_filter_exe` (invoked via thunk `0x140018C0C`), which
   `TerminateProcess`es with `0xC0000005`. The occasional `0xC0000409`
   fast-fail terminus is the same fault manifesting as an MSVC stack-cookie
   check failure at `__report_gsfailure` (0x140017F84) when the AV happens
   inside a cookie-protected function's epilogue path — same class, same root.

The two participants — the guest's MBI-vector walker and the emulated ntdll's
periodic MEM_DECOMMIT — are both **faithful**. Al-khaser is running its real
detection code; the emulated ntdll IS a real Windows 10 ntdll.dll (from the
deps bundle) executing its real segment-heap decommit paths. The bug is in
neither.

**What differs from real Windows is the timing distribution across the walk**.
On real hardware the same walker completes in ~ms; the segment heap's
delayed-coalesce / decommit pass doesn't fire on µs granularity between
one page's snapshot and its read. In Brovan every instruction runs
sequentially with per-`RtlEnterCriticalSection` / `RtlpAllocateHeap` /
`GetModuleHandleExW` cost, so `GetModuleHandleExW` calls during the walk
provide many more heap-allocator opportunities per unit of *guest time*
than they would on hardware, tripping the decommit threshold from **inside**
the walker itself. The specific arena being walked gets decommitted under
the walker; the snapshot goes stale; the read faults.

**Why this is not routed to `Boundary`** (verdict rule #14): the sample IS
being terminated by a `0xC0000005` from its own code path — that's an honest
`Error` verdict, not a natural boundary at an external dependency. Faking
this as `Boundary` would hide the fact that al-khaser's own written contract
(no SEH around its detection functions, relying on the impossibility of
fault) is being exercised, and would set a precedent for masking any similar
timing race in future samples. The verdict stays honest.

**Why this is not fixable by a Brovan-side patch** (verdict rule #14 + rule #6):

- Making `DecommitMemory` a metadata-only flip that leaves the Unicorn
  mapping alive so subsequent reads succeed **would diverge from Windows
  semantics** (real Windows returns `STATUS_ACCESS_VIOLATION` for a read
  of a decommitted page); a probe that deliberately reads a decommitted
  page to fingerprint the emulator would flag Brovan.
- Preventing the emulated ntdll heap from calling `NtFreeVirtualMemory` is
  impossible — that's the real ntdll's own decommit code path.
- Retimed / batched / synthesised decommit is sample-specific tuning (rule
  #6) — the trigger is a legitimate memory-pressure signal, not a stub gap.
- Wrapping the guest's read in emulator-side SEH so al-khaser survives its
  own bug would also be sample-specific and mask the real signal.

**Result of this pass**: the 44 GOOD / 4 BAD verdict for probes that complete
before the walker is stable; the walker terminus itself remains an honest
`Error(0xC0000005)`. All the value from the earlier probes is preserved.
The trace exposes both the `[GOOD]` /  `[ BAD ]` per-probe lines and the
terminus code — the log alone tells the correct story.

**Deferred as a future direction, not landed here**: the segment-heap
decommit threshold might be soft-nudged by pre-populating a larger initial
`RtlpHeapReservedBytes` field in the PEB so ntdll thinks it has more
committed slack; this could delay the decommit past the walker's completion
without patching semantics. It is a research direction, not a landed fix,
and needs a validation strategy on other samples (rule #6) before shipping.

All diagnostic instrumentation from this pass has been reverted; tree
stays clean.

### Landed this pass — the four residual BAD probes → GOOD (48 GOOD / 0 BAD)

After the walker-terminus was diagnosed, the four residual `BAD` verdicts
that ran to completion before the terminus were investigated individually
against al-khaser's own upstream source. Every one was a concrete stub gap,
not an intrinsic frontier. All four landed as generic, per-syscall fidelity
fixes with no sample-specific tuning; verdict is **48 GOOD / 0 BAD stable
across 5 consecutive runs** (both the ~47 M `Fast-Fail` interleaving and
the ~72 M `0xC0000005` interleaving reach the terminus with an identical
per-probe verdict distribution). The walker-terminus itself is unchanged
— the sample still exits `Error`, but every visible probe result is now
correct.

- **`NtSetInformationThread(ThreadHideFromDebugger)`** — the stub always
  returned `SUCCESS`, ignored the length argument, and stored nothing.
  al-khaser probes it with (1) a bogus 12345 length expecting
  `STATUS_INFO_LENGTH_MISMATCH`, (2) a bogus 0xFFFF handle expecting
  `STATUS_INVALID_HANDLE`, then (3) a valid `Set(NULL, 0)` followed by
  (4) 8 unaligned `Query(size=4, ptr=buf+i)` reads for `i∈[0,7]`
  expecting `STATUS_DATATYPE_MISALIGNMENT` on offsets 1/2/3/5/6/7 and
  `STATUS_INFO_LENGTH_MISMATCH` on the aligned 0/4, plus (5) a final
  `Query(size=1)` expecting the hidden flag byte to read back as `1`.
  Fixes: length-not-zero on Set → `INFO_LENGTH_MISMATCH`; track hidden
  flag on `WindowsThreadState.HiddenFromDebugger`; on Query, do the
  ntoskrnl `ProbeForWrite(sizeof(ULONG))` alignment check FIRST (length
  ≥ 4 && unaligned → `DATATYPE_MISALIGNMENT`), then the strict size
  check (`!= 1` → `INFO_LENGTH_MISMATCH`), then return the flag byte.
- **`Int 0x2D` (`KiDebugService`)** — the WindowsGuest interrupt handler
  had cases 1 / 3 / 0x29 / 0x2E but not 0x2D, so `int 0x2D` was silently
  dropped and al-khaser's VEH never saw the expected `STATUS_BREAKPOINT`,
  so its `SwallowedException` flag stayed `TRUE` and the probe reported
  BAD. Fix: `case 0x2D: QueueUserModeException(STATUS_BREAKPOINT)` mirrors
  the `int 3` path; the CPU/kernel already advances RIP past the CD 2D
  opcode by the time the exception is delivered, matching the VEH's
  "already advanced" expectation with no extra RIP fixup needed.
- **`SeDebugPrivilege`** — al-khaser's probe is a compact
  `OpenProcess(csrss.exe, PROCESS_QUERY_LIMITED_INFORMATION)` — a
  non-`NULL` handle means the caller has `SeDebugPrivilege` (only
  privileged callers can open a protected system process). Brovan's
  `NtOpenProcess` allowed `PROCESS_QUERY_LIMITED_INFORMATION` on
  protected processes regardless of caller elevation, so the probe got
  a handle back and reported BAD. Fix: for any protected process
  (`ProtectionStatus != None` — `LightTCB` covers csrss / wininit /
  services / winlogon, `LightAM` covers MsMpEng / MpDefenderCoreService),
  return `STATUS_ACCESS_DENIED` unconditionally unless the caller's
  primary token has `IsElevated = true`. This is real-Windows behaviour
  (protected processes are opaque to non-elevated callers even for
  `QUERY_LIMITED_INFORMATION`) and generalises across every protected-
  process detection variant, not just csrss.
- **`NtYieldExecution`** — the stub returned `STATUS_SUCCESS` on every
  call. al-khaser calls `NtYieldExecution` 20 times (with `Sleep(15)`
  between each) and increments a counter on every non-
  `STATUS_NO_YIELD_PERFORMED` return; the counter is compared against
  `<= 3` for GOOD. Real bare-metal Windows returns `NO_YIELD_PERFORMED`
  the vast majority of the time (nothing else is Ready to run), so the
  counter never exceeds a few. Brovan returned SUCCESS on all 20 → BAD.
  Fix: scan the emulator's thread table for any `EmulatedThreadState.Ready`
  peer; if none, return `STATUS_NO_YIELD_PERFORMED`; otherwise mark the
  caller Ready and stop-emulate exactly as before. This is the correct
  scheduler semantics on any surface, not just this probe. The new
  `NTSTATUS.STATUS_NO_YIELD_PERFORMED = 0x40000024` was added to the
  enum (was missing).

Fast test suite green through this pass; tree stays clean.

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

### F5 — x86 / WOW64 — foundation landed, loader now runs deep into process init

**Original symptom:** `al-khaser_x86.exe` did not run at all — it died immediately
with `ntdll.dll is not loaded` before executing a single guest instruction.

**Status now:** the WOW64 foundation is implemented and validated. A 32-bit PE
loads the real 32-bit ntdll from the `SysWOW64` view, builds a valid 32-bit
process environment, dispatches WOW64 system calls through a synthetic
`sysenter` trampoline with the correct SSNs, handles CPU/software exceptions
through the x86 `KiUserExceptionDispatcher`, and runs ntdll's `LdrInitializeThunk`
loader **all the way through image loading into DLL initialisation** — synthesising
the WOW64INFO block, reserving the CFG bitmap, opening the process memory partition,
creating the NT process heap, resolving the KnownDlls object-manager chain, mapping
the real 32-bit `kernel32` / `kernelbase` / CRT from the `SysWOW64` view, running
their DllMains **to completion** (the CSR base-server connect + read-only
shared-section / `BASE_STATIC_SERVER_DATA` are now wired), and driving on into
process init — reaching **~6.31M guest instructions**, up from ~8k at the start of
this line of work. `STATUS_DLL_INIT_FAILED` is cleared; it now terminates further
along at `APP_INIT_FAILURE` `Parameter0=0xC0000004` (`STATUS_INFO_LENGTH_MISMATCH`
from `NtSetInformationProcess` — the current frontier below). The x64 cohort is
structurally unaffected by these x86 fixes (every fix is either x86-only-gated or in
a WOW64 `if`-branch).

**Environment note (reproduction):** `WindowsLibs/` must be a *real* directory
inside the emulator output dir, not a symlink pointing outside it. The path sandbox
(`GetSandboxedFullPath`) resolves symlink targets and rejects anything outside the
allowed roots, so a `WindowsLibs -> /elsewhere` symlink makes every system-DLL
resolution silently miss (both bitnesses then fail to load `kernel32` with
`STATUS_DLL_NOT_FOUND`). Copy the bundle in; don't symlink it.

This whole subsection is the WOW64 model. **The design decision that makes it
tractable: emulate a 32-bit process purely in `UC_MODE_32`** — one Unicorn
context, never the real Heaven's-Gate 0x33 mode switch. The 32-bit ntdll's
`Nt*` stubs reach the kernel through `Wow64Transition` / `fs:[0xC0]`; Brovan
points both at a trampoline that runs a `sysenter` it intercepts, dispatching to
the same C# `Nt*` handlers the x64 path uses. The SSNs in the WOW64 32-bit ntdll
are **identical to the native x64 SSNs** (NtCreateFile = 0x55, NtProtectVirtualMemory
= 0x50 on both), so the number→name mapping is built the same way — by parsing
the guest ntdll's `mov eax, imm32` stub prologues, now from `WindowsLibs/SysWOW64/ntdll.dll`.

#### Landed WOW64 primitives

- **SysWOW64 dependency view** (`GeneralHelper.Wow64GuestView`, an ambient flag
  set from the binary architecture at guest bring-up). On a non-Windows host the
  WindowsLibs resolver (`GetWindowsLibPath`, `TryResolveFromWindowsLibs`,
  `TryResolveFromWindowsLibsByLeaf`) redirects a 32-bit guest's `System32`
  requests to `WindowsLibs/SysWOW64` — the emulator-side WOW64 file-system
  redirector. Falls back to the flat view when SysWOW64 doesn't ship a file.
- **x86 syscall table** — `BuildWinSyscallDictionary(x86)` reads
  `SysWOW64/ntdll.dll` + `win32u.dll` (was reading the flat 64-bit ntdll for both
  arches).
- **Bitness-aware GPR transfer** (`BinaryEmulator.ReadGprBatch/WriteGprBatch`).
  Root cause of the very first crash: **Unicorn treats the 64-bit register IDs
  (`RAX`/`RSP`/`RIP`/… ids 35, 41, 44, …) as no-ops in `MODE_32`** — writing them
  silently does nothing, reading returns 0. So the thread context never reached a
  32-bit CPU (ESP stayed 0 → `push` faulted at `LdrInitializeThunk`). The batch
  now uses the 32-bit IDs (`EAX`/`ESP`/`EIP`/`EFLAGS`, 10 regs, no R8-R15) when
  `BackendMode == MODE_32`.
- **GDT-based FS base** (`WindowsGuest.SetupWow64Segments` + a new
  `IEmulationBackend.WriteGdtr` MMR-write primitive on all backends). `MODE_32`
  also ignores the `FS_BASE` pseudo-register (`fs:[0x18]` faulted), so the FS base
  is installed through a real GDT descriptor (selector 0x50, GDT index 10) reached
  via GDTR; the descriptor's base is rewritten to the current thread's TEB on each
  context switch and FS reloaded. Loading a custom GDTR turns the default `SS=0`
  into a null selector (stack pushes then `#GP`), so `SS`/`DS`/`ES` are reloaded
  with flat DPL0 selectors. **Selectors are DPL0/RPL0, not the real WOW64 ring-3
  values (CS 0x23, FS 0x53):** a ring-3 selector can only be loaded at CPL 3, and
  Unicorn's `reg-write` of CS does not perform the far transfer that raises CPL, so
  RPL-3 loads `#GP`. The FS base is still correct (all `fs:[X]` resolve); the
  visible selector *values* differ — a known cosmetic gap, tracked below.
- **32-bit process environment** (`WindowsGuest.BuildProcessEnvironment32`) — full
  32-bit PEB + `RTL_USER_PROCESS_PARAMETERS` (documented x86 offsets, UNICODE_STRING
  buffer at struct+4). Previously only a minimal PEB was built, and only for the
  raw-blob path; a real 32-bit PE got no ProcessParameters and the loader read a
  NULL command line.
- **32-bit TEB** (`AllocateAndInitializeTEB`) — built for every 32-bit guest now,
  including `WOW32Reserved` (`fs:[0xC0]`) pointed at the syscall trampoline.
- **WOW64 syscall trampoline** (`SetupWow64SyscallTransition`) — a
  `pop edx ; sysenter ; push edx ; ret` page. `pop` discards the ntdll-stub return
  address that `call fs:[0xC0]` / `jmp [Wow64Transition]` leaves on top, so at the
  `sysenter` ESP points at the *caller's* return address with the syscall args at
  ESP+4, ESP+8, … — exactly what `GetArg32` expects. `push` restores it so the
  final `ret` returns into the stub's `ret N`, cleaning the stdcall args. Both the
  ntdll `Wow64Transition` global and the per-thread TEB `fs:[0xC0]` point at it; a
  new `SYSENTER` instruction hook (registered only for `MODE_32`) routes to the
  same `TryHandleSyscall` the x64 `SYSCALL` hook uses.
- **32-bit thread bootstrap** (`CreateEmulatedThread` x86 path +
  `BuildInitialContext32`) — `LdrInitializeThunk` is entered stdcall-style with a
  `CONTEXT*` first arg; it `NtContinue`s to a 32-bit CONTEXT whose Eip is
  `RtlUserThreadStart` with Eax = entry, Ebx = parameter (the x86 ABI).
- **x86 CONTEXT handling** — `NtContinue`, `NtRaiseException`, and the exception
  dispatcher (`WinSysHelper.DispatchExceptionX86` reached from `InvokeException`)
  all read/write the 32-bit CONTEXT (0x2CC) layout with the 32-bit register IDs.
  The x86 `KiUserExceptionDispatcher` ABI (`[esp]=PEXCEPTION_RECORD`,
  `[esp+4]=PCONTEXT`, confirmed from its stub prologue) is built on the thread
  stack. Before this, any fault/exception spun ~20M no-op instructions
  (`InvokeException is only implemented for x64`); now SEH dispatches correctly and
  the run terminates.
- **Unified syscall argument reading** (`WinSysHelper.GetArg64` delegates to the
  stack-based `GetArg32` in `MODE_32`) so the ~130 handlers that read args through
  `GetArg64` without an explicit arch branch get correct 32-bit arguments for free;
  and pointer-sized OUT writes go through new bitness-aware
  `BinaryEmulator.ReadPointer` / `WritePointer` / `GuestPointerSize` helpers.
- **Pseudo-handle helpers** (`WinSysHelper.IsCurrentProcessPseudoHandle` /
  `IsCurrentThreadPseudoHandle`) — the `(HANDLE)-1` current-process pseudo-handle
  arrives as `0xFFFFFFFF` (zero-extended) on x86, not `ulong.MaxValue`, so bare
  `== ulong.MaxValue` comparisons missed it.
- **Handlers made bitness-aware** (args unified, OUT structs sized to the guest):
  `NtProtectVirtualMemory`, `NtQuerySystemInformation` (incl. the x86 44-byte
  `SYSTEM_BASIC_INFORMATION`), `NtQueryInformationProcess`
  (ProcessBasicInformation / ProcessCookie / ProcessDefaultHardErrorMode /
  ProcessExecuteFlags / ProcessImageInformation — x86 `SECTION_IMAGE_INFORMATION`
  0x30), `NtQueryVirtualMemory` (MemoryBasicInformation 0x1C / MemoryImageInformation
  0x0C / MemoryWorkingSetExInformation 8-byte entries),
  `NtQueryInformationThread` (ThreadBasicInformation 0x1C), `NtCreateEvent`,
  `NtCreateSection`, `NtMapViewOfSection`, `NtSetInformationProcess`,
  `NtContinue`, `NtRaiseException`.

**Progression (instruction terminus grows as each layer landed):**

| Stage | Terminus |
|-------|----------|
| Session start | `ntdll.dll is not loaded` — 0 guest instrs |
| SysWOW64 view + syscall table | 32-bit ntdll loads; crash at `LdrInitializeThunk` `push ebp`, ESP=0 |
| Bitness-aware GPR batch | thread starts; `fs:[0x18]` fault (FS base unset) |
| GDT-based FS + 32-bit TEB/PEB/CONTEXT + trampoline | WOW64 syscalls dispatch with correct SSNs |
| Unified args + loader-critical handlers | loader queries + maps DLL sections |
| x86 exception dispatch | infinite no-op spin gone; SEH dispatches; clean terminus |
| ProcessImageInformation / thread / memory classes | loader runs ~8k instrs deep into init |
| WOW64INFO in TEB TlsSlots[10] | CPU-feature init deref fixed → ~20k instrs (CFG-bitmap reserve reached) |
| SystemEmulationBasicInformation MaximumUserModeAddress | CFG-bitmap span computes non-zero → ~21.6k (segment-heap init reached) |
| NtOpenPartition | memory partition opens → segment-heap arena allocates → ~22.1k (heap tree build reached) |
| RTL_USER_PROCESS_PARAMETERS header size (0x2A0→0x300) | HeapPartitionName no longer garbage → NT heap (not segment heap) → ~128k (KnownDlls chain reached) |
| KnownDlls object-manager + file handlers → WOW64 | NtOpen{DirectoryObject,SymbolicLinkObject,Section}, NtQuery{SymbolicLinkObject,AttributesFile} → ~181k (DLL disk-load reached) |
| SysWOW64 case-insensitive leaf resolution | 32-bit kernel32/kernelbase/CRT bind (not the 64-bit copy) → ~1.34M (DLL init reached) |
| CSR base-server connect (`NtWow64CsrClientConnectToServer`, SSN 0x1D7) | kernel32/kernelbase `BaseDllInitialize` reaches the CSR handshake |
| CSR read-only shared section + `BASE_STATIC_SERVER_DATA` (PEB +0x4C/+0x54/+0x248) | `BaseDllInitialize` completes → **~6.31M** (`DLL_INIT_FAILED` cleared) |
| `NtSetInformationProcess(ProcessTlsInformation)` WOW64 element size (0xC not 0x18) | ntdll deferred-TLS setup succeeds → **~9.93M** (`INFO_LENGTH_MISMATCH` cleared) |
| `NtSetInformationVirtualMemory` + `NtQueryInformationProcess(ProcessMitigationPolicy)` → WOW64 | CFG registration + mitigation query succeed (advisory) → later-DLL init |
| user32 win32k client-connect (`NtUserProcessConnect`, syscall 0x2000) + SHAREDINFO | user32 DllMain passes the connect → **~9.98M** |
| WOW64 registry family (`NtOpenKey`/`NtQueryValueKey`/… ×13) | registry works on x86 (prereq for the detection phase) |
| *(open)* gdi32full per-thread GDI `CLIENTINFO` (`TEB+0x60`) | current terminus — GDI client subsystem, see frontier below |

#### Resolved this pass (each fix is a generic WOW64 fidelity correction)

1. **WOW64INFO structure + `TEB.TlsSlots[WOW64_TLS_WOW64INFO]` (offset 0xE38).**
   The earlier `mov eax, [eax]` fault at guest `0x4B32A880` (`eax == 0`) was
   ntdll's CPU-feature/page-size init dereferencing `TlsSlots[10]`. On a real
   WOW64 process `wow64.dll` allocates a process-wide `WOW64INFO` block and stores
   its pointer in that slot (in *both* the 32- and 64-bit TEBs) *before* the 32-bit
   ntdll runs; the pure-32-bit model has no `wow64.dll`, so the slot was NULL. Fixed
   in `WindowsGuest.SetupWow64Info` (one block per process) + a per-TEB write in
   `AllocateAndInitializeTEB`. Layout confirmed by disassembling `SysWOW64\ntdll`
   (three read sites at RVA 0xAA872 / 0x9E5B4 / 0x5BE6E, cross-checked against the
   x64 sibling at RVA 0xC5792 which NULL-guards the same slot): `NativeSystemPageSize`
   @0x00 (0x1000 → ntdll bit-scans it to page-shift 12), `CpuFlags` @0x04 (bit 0x2
   set → ntdll routes `RtlQueryPerformanceCounter` through the syscall transition
   instead of the unimplemented `int 0x81` fast path), `NativeMachine`=0x8664 @0x20,
   `EmulatedMachine`=0x014C @0x22.

2. **`SystemEmulationBasicInformation` (`NtQuerySystemInformation` class 0x3E)
   `MaximumUserModeAddress`.** ntdll's CFG-bitmap reservation reads this value back,
   does `MaximumUserModeAddress + 1`, and derives the bitmap span from it. The WOW64
   branch was returning `(uint)Instance.MaxAddress` = `0xFFFFFFFF` (the emulator's
   *internal* 34-bit allocation ceiling truncated to 32 bits), whose `+1` overflows
   to 0 → a 0-byte `NtAllocateVirtualMemoryEx` → `STATUS_INVALID_PARAMETER` →
   `STATUS_APP_INIT_FAILURE`. Now reports the real Win32 process bounds: floor
   `0x00010000` (64 KB), ceiling `0x7FFEFFFF` (2 GB − 64 KB), or `0xFFFEFFFF`
   (4 GB − 64 KB) when the image is `IMAGE_FILE_LARGE_ADDRESS_AWARE`. Root-caused by
   walking the CFG-bitmap call chain in ntdll (RVA 0xF2593 → 0xFE480 bitmap-size
   math → 0xF5F86 span → 0xF09DD `NtQuerySystemInformation(0x3E)`).

3. **`NtOpenPartition` (SSN 0x126).** ntdll's segment-heap init opens the process's
   memory partition during startup. Unimplemented, it returned `STATUS_NOT_SUPPORTED`;
   although the ntdll caller (RVA 0xB2FD2) tolerates the failure by branching around
   the partition-setup path, the process is then left with no partition and heap init
   aborts with `STATUS_NO_MEMORY` → `STATUS_APP_INIT_FAILURE`. Every process really
   does belong to a partition (the system partition is the implicit default), so the
   faithful behaviour is a valid handle. Added a `WinPartition` handle object
   (`HandleType.PartitionHandle`) + `CreatePartitionHandle` + the `NtOpenPartition`
   handler (bitness-agnostic via `GetArg64`/`WritePointer`).

**Segment-heap fast-fail — RESOLVED.** The earlier terminus (a `__fastfail`,
`FAST_FAIL_INVALID_BALANCED_TREE`, in the segment heap's `RtlpHpVs*` free-chunk
tree) was a *downstream symptom*: ntdll had wrongly selected the **segment heap**
for a classic 32-bit process (which uses the **NT heap**). The root cause was traced
through `RtlCreateHeap` → `RtlpHpHeapFeatures` → `RtlpHpShouldEnableSegmentHeap`,
which for a non-packaged process reads `RTL_USER_PROCESS_PARAMETERS + 0x2B0`
(`HeapPartitionName.Buffer`) and enables the segment heap when it is non-NULL.
`BuildProcessEnvironment32` had sized the fixed header at only 0x2A0 and started the
inline string buffers there, so the CurrentDirectory path string bled into
`HeapPartitionName.Buffer`. Sizing the header to 0x300 leaves that field NULL → NT
heap → no VS tree → the fast-fail is gone. (See "Resolved this pass" table row.)

#### Current frontier (F5-next)

With the NT heap, the KnownDlls object-manager chain, case-correct SysWOW64
resolution, the CSR base-server connect (SSN 0x1D7) **and the CSR read-only
shared-section wiring** all landed, the loader now maps the real 32-bit `kernel32`
/ `kernelbase` / CRT, runs their DllMains to completion, and drives on into process
init — reaching **~6.31M instructions**, up from ~1.34M. DLL initialisation now
**succeeds** (`STATUS_DLL_INIT_FAILED` is gone); the run terminates further along at
`APP_INIT_FAILURE` with `Parameter0=0xC0000004` (`STATUS_INFO_LENGTH_MISMATCH`).

**Resolved this pass — CSR read-only shared section / `BASE_STATIC_SERVER_DATA`.**
The `DLL_INIT_FAILED` was root-caused by disassembling kernelbase's `BaseDllInitialize`
from live guest memory: right after `NtWow64CsrClientConnectToServer` returns, the
inner init reads `PEB->ReadOnlyStaticServerData` (32-bit PEB **+0x54**) and derefs
`[array+8]` to reach the BASESRV static-server-data pointer, then remaps it with
`edi = ReadOnlyStaticServerData[1] - ServerBase(PEB+0x248) + ReadOnlySharedMemoryBase(PEB+0x4C)`.
All three PEB fields were NULL, so the deref faulted (`Invalid memory read … 0x8 …`),
`BaseDllInitialize` returned FALSE, and the loader rolled the process back. The remap
reads `[BSSD+0x9E8]` — the exact self-pointer the x64 `InitializeWindowsSharedSection`
already writes — confirming **WOW64 shares the native 64-bit BSSD layout** (16-byte
UNICODE_STRINGs, 8-byte pointers). Fix (`WindowsGuest.SetupCsrReadOnlySharedSection32`):
eagerly create the read-only shared section at PEB-build time via the reused
`NtMapViewOfSection.InitializeWindowsSharedSection`, then wire `PEB+0x4C` = section
base, `PEB+0x54` = the section's `Base+0x10` server-data descriptor (whose `+0x8`
already points at BSSD), and `PEB+0x248` = section base. Server view == client view
(Brovan has no separate csrss address space), so the remap is the identity and the
descriptor's absolute BSSD pointer resolves to itself. x64 guests reach BSSD through
the CSR port connect reply instead, so this is WOW64-only and leaves x64 untouched.

**Resolved next — `NtSetInformationProcess(ProcessTlsInformation)` WOW64 sizing.**
The `0xC0000004` terminus was ntdll's `LdrpQueueDeferredTlsData` calling
`NtSetInformationProcess(ProcessTlsInformation, len=0x1C)` and the handler rejecting
it: the handler hardcoded the x64 `THREAD_TLS_INFORMATION` element size (0x18) so
`0x1C < 0x10 + 0x18` gave `INFO_LENGTH_MISMATCH`. Disassembling the ntdll caller
(`imul eax, count, 0xC; add eax, 0x10; push eax`) confirmed the WOW64 element is
`Flags(4)+NewTlsData(4)+ThreadId(4) = 0xC`, and the TEB TLS-vector slots are 4-byte.
Fix: the handler now derives every width from `GuestPointerSize` — element size
`0xC`/`0x18`, field offsets, `TEB.ThreadLocalStoragePointer` at `0x2C`/`0x58`, and
pointer-sized vector reads/writes (`ReadPointer`/`WritePointer`). x64 is byte-identical
(Ptr=8 reproduces the former 0x18/0x58/8 constants). al-khaser advances **6.31M →
~9.93M** instructions.

**Resolved next — WOW64 `NtSetInformationVirtualMemory` + `NtQueryInformationProcess(ProcessMitigationPolicy)`.**
Both were x86-gated to `NOT_SUPPORTED`. `NtSetInformationVirtualMemory` (SSN 0x19E,
CFG call-target registration + working-set hints) is now bitness-aware — the
`MEMORY_RANGE_ENTRY` stride is `2*GuestPointerSize` (8 on x86) and the pseudo-handle
check uses `IsCurrentProcessPseudoHandle` — returning the same advisory success the
x64 path does. `NtQueryInformationProcess`'s x86 branch gained the
`ProcessMitigationPolicy` (class 52) case: the WOW64 caller passes an 8-byte
`PROCESS_MITIGATION_POLICY_INFORMATION` with the policy id in the first DWORD; the
handler echoes it and reports the sandbox's realistic state (DEP on, other
mitigations default), mirroring the x64 class-52 handler. Both now return SUCCESS in
the trace; the CFG-registration burst is advisory (its result is ignored — the
instruction count was byte-identical with it as `NOT_SUPPORTED` vs SUCCESS).

**Resolved — user32's win32k client-connect (syscall `0x2000`).** The `0x2000`
terminus was traced (via the caller return address) to **`user32.dll`'s `DllMain`**
(`_UserClientDllInitialize`): a CFG-protected win32k client-connect, stub `mov eax,
0x2000; call <thunk>; ret 0x10` (4 args), whose sign-checked result aborts `DllMain`
on failure. It is `NtUserProcessConnect` in spirit but uses user32's **internal** stub
(SSN `0x2000`), distinct from win32u's exported `NtUserProcessConnect` (SSN `0x10e9`,
2-arg) — the win32u export scan therefore never registered it. Landed: a
`Win32k/NtUserProcessConnect` handler bound to SSN `0x2000` in the x86 path. The out
buffer is a `USERCONNECT` (8-byte version header, then `SHAREDINFO` at `+0x08` —
confirmed empirically: writing a value there is what user32 reads back as `psi`); the
handler fills `psi` / `aheList` / `HeEntrySize` / `pDispInfo` from the emulator's
existing `EnsureUserSharedInfo` + `EnsureUserDesktopInfo` (the same win32k
SERVERINFO/handle-table the x64 CSR `HandleUserSrvConnect` builds) and returns
`STATUS_SUCCESS`. user32 now passes the connect + the `test byte [psi],4` deref,
advancing **~9.94M → ~9.98M** instructions.

**Next frontier — gdi32full's per-thread GDI `CLIENTINFO` (the current fatal deref).**
Pinned precisely: the fault is in **`gdi32full.dll`** (the ~2.1 MB module the WOW64
loader maps at `~0x10320000`; fault IP `0x1044AF1C`). Its per-thread GDI init reads
`mov eax, fs:[18h]` (32-bit TEB, confirmed at `0x10016000`) → `mov ecx, [TEB+0xFDC]`
(== 0, so the `jns`/`add` keeps the base at the TEB) → `mov eax, [TEB+0x60]` (== 0,
the NULL) → `mov eax, [eax+0xF8]` (**faults**) → `cmp [eax+0x180094], …`. `TEB+0x60`
is the per-thread GDI client-info pointer (`CLIENTINFO`/`pti`) that win32k sets on GDI
thread-attach; it is NULL because Brovan never wires it for WOW64. The chain is a
multi-level structure walk — `CLIENTINFO → [+0xF8] → [+0x180094]` — and `0x180094` is
an index into the **GDI shared handle table** (0x10-byte x86 entries ⇒ ~98 K entries,
a deliberately large reserve). The emulator already builds that table
(`WinSyscallsHelper.EnsureGdiHandleTable` / `GdiHandleTableAddress`, used by the x64
`HandleUserSrvConnect` path), so the remaining work is (a) allocate + zero a 32-bit
`CLIENTINFO`, wire `TEB+0x60` (and likely `TEB+0x40` `Win32ThreadInfo`) to it during
the WOW64 TEB/connect setup, and (b) populate the `CLIENTINFO` fields gdi32full walks
(`[+0xF8]` → the GDI shared base, with a valid entry at `+0x180094`). This needs the
exact 32-bit `CLIENTINFO` layout reverse-engineered from gdi32full — a bounded but
non-trivial GDI-client-state piece; guessing the offsets would only move the fault a
few dereferences deeper, so it wants a dedicated pass, not an incremental patch.

The **x86 registry** sibling gap is now closed (see below).

**Landed alongside — WOW64 registry syscalls.** The same DLL init was issuing a burst
of `NtOpenKey` (SSN 0x12) returning `NOT_SUPPORTED` because the whole registry family
was gated to x64. All 13 handlers are now bitness-agnostic: a new
`TryResolveRegistryObjectPath` reads the correct `OBJECT_ATTRIBUTES` (4-byte fields +
8-byte `UNICODE_STRING` on x86 / 8-byte fields + 16-byte on x64), a `TryReadUnicodeString`
wrapper picks the value-name layout by bitness, and OUT `KeyHandle`s are written with
`WritePointer`/`GuestPointerSize`. The flat `KEY_*_INFORMATION` output records are
identical on both bitnesses, so the handle-returning handlers (`NtOpenKey`/`NtOpenKeyEx`/
`NtCreateKey`) took the pointer treatment while the data handlers
(`NtQueryValueKey`/`NtEnumerate{Key,ValueKey}`/`NtQueryKey`/…) just widened their gate.
This does not move the terminus (the `CLIENTINFO` deref is still fatal) but is
**essential** for the detection phase — al-khaser's anti-VM logic reads dozens of
registry keys, so WOW64 registry is squarely on the critical path once GUI init clears.
x64 registry behaviour is byte-identical (the old `…64` resolver now forwards to the
shared one; the widened gates still enter on x64). Other still-unimplemented syscalls
(`0x1E9` `NtWow64IsProcessorFeaturePresent`; `0x1CE`; `NtQuerySystemInformation` class
0x73) are not (yet) on the fatal path.

**Remaining WOW64 work (mechanical continuation):** the other x64-gated `Nt*`
handlers still return unimplemented for x86 — each needs the same treatment (unify
args via `GetArg64`, size OUT pointers/structs to the guest via `WritePointer` /
the 32-bit OBJECT_ATTRIBUTES / UNICODE_STRING readers, fix `(HANDLE)-1` pseudo-handle
comparisons). The pattern is well established now (five handlers landed this pass);
extend it handler-by-handler as the DLL-init and detection phases exercise them.

**Remaining WOW64 work (mechanical continuation):** the other ~70 `Nt*` handlers
gated `if (Architecture == x64)` still return unimplemented for x86 — each needs
the same treatment (unify args via `GetArg64`, size OUT pointers/structs to the
guest, fix `(HANDLE)-1` pseudo-handle comparisons). The pattern is established;
extend it handler-by-handler as al-khaser's detection suite exercises them.

#### Reproduction (x86)

```bash
# Deps: WindowsLibs/ (+ SysWOW64/), WinReg/, apisetmap.bin next to Brovan.dll.
# Unicorn 2.1.4 is fetched by the build (or stage libunicorn.so into .cache).
# UC_IGNORE_REG_BREAK=1 silences MODE_32 register-deprecation warnings on stderr.
UC_IGNORE_REG_BREAK=1 printf 'start\nexit\n' | dotnet Brovan.dll al-khaser_x86.exe
```

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
