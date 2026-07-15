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

al-khaser now loads fully, runs its detection suite, walks the PEB loader lists,
enumerates its modules, and prints its verdicts. The remaining terminus is a
threading frontier (F1) plus raw emulation throughput (F2).

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

- `dotnet build` writes to `bin/Release/net8.0/`, **not** `bin/Release/net8.0/linux-x64/`
  (the deps live in the latter). After building, copy `Brovan.dll` across, or
  run from `net8.0/` with the deps beside it. Running the stale `linux-x64`
  binary silently masks code changes.
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
  timing of later runs. `pkill -9 -f Brovan.dll` between runs.

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

### F2 — Emulation throughput

**Symptom:** even the progressing run needs well over 240 s to finish al-khaser's
full suite (it enumerates 96 modules in ~2 min).

**Note:** this is performance, not a correctness bug — al-khaser genuinely
executes a large amount of code. It only *looks* like a hang because the run
budget is too short. Relevant if the goal is a clean end-to-end verdict rather
than partial coverage.

### F3 — Injected-library false positive

**Symptom:** al-khaser's injected-library check now runs (good) but flags
**every** legitimate system DLL (`sechost.dll`, `RPCRT4.dll`, `ole32.dll`, …) as
"injected".

**Root-cause hypothesis:** the per-module "is this legitimate" predicate
(al-khaser `0x14000c0c0`) fails for Brovan's modules — most likely because they
are not backed by a mapped-file section the way real loaded modules are (e.g.
`NtQueryVirtualMemory(MemorySectionName / MemoryMappedFilenameInformation)` does
not return the on-disk path for a module's address range). A real anti-analysis
sample keying on this would mis-classify, so it is a stealth/realism gap.

**Recommended approach:** make each loaded guest module's address range answer
`NtQueryVirtualMemory` section-name queries with its `\Device\HarddiskVolumeN\...`
image path, so the module reads back as file-backed.

### F4 — `FILE_OVERWRITE_IF` create of a file in the sample's own directory

**Symptom:** al-khaser repeatedly tries to create its `log.txt` next to the
executable (`NtCreateFile` disposition 5 = `FILE_OVERWRITE_IF`) and gets
`STATUS_OBJECT_NAME_NOT_FOUND` instead of a created handle. Observed path:
`\??\\tmp\...\alkhaser\x64\log.txt` (note the doubled separator after `\??\`).

**Root-cause hypothesis:** the sample's working-directory NT path (built from the
host path where the `.exe` lives) does not round-trip through
`ResolveWindowsFilePath` / `CreateOrTruncateFile`, so the create fails. Non-fatal
today (al-khaser continues without its log) but it means dropped-file behaviour
in the sample's own directory is not captured.

**Recommended approach:** verify NT-path normalisation for a working directory
that is an arbitrary host path with `\??\` prefix and doubled separators; ensure
`FILE_OVERWRITE_IF` / `FILE_OPEN_IF` for a non-existent file creates it in the
virtual FS.

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
