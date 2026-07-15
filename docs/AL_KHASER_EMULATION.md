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

al-khaser now loads fully, runs its detection suite, walks the PEB loader lists,
enumerates its modules, and prints its verdicts. The last three fixes do not move
the instruction terminus — they close specific behavioural/stealth gaps
(dropped-file capture, injected-DLL prerequisites) or reclaim throughput. The
remaining termini are a threading frontier (F1), the NLS-collation residual
behind the injected-DLL false positive (F3), and — measured this pass — a
throughput picture (F2) where raw per-instruction speed is already healthy so
the wall-time is instead dominated by F1's spin and F3's NLS re-open storm.

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

- Build with the **.NET 9 SDK** (`/opt/dotnet/dotnet`, 9.0.x), not the distro
  `/usr/bin/dotnet` (8.0.x). `which dotnet` may resolve to the 8.0 one, which
  loads the `Brovan.Generators` Vulkan source generator against Roslyn 4.8 and
  silently emits nothing — the build then fails with ~23 `CS0103 'BvkMK' /
  'BrovVulkStructMeta' does not exist` errors that look like broken source but
  are just the wrong SDK. `export PATH=/opt/dotnet:$PATH` first. The target
  framework stays net8.0.
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

**Residual (see F3 below).** With the prerequisites correct the false positive
still stands: the case-insensitive comparison returns "not equal" for equal
strings. `StrCmpNIW`/`StrCmpIW` are thunks → apiset
`api-ms-win-core-shlwapi-obsolete` → `kernelbase!StrCmpNIW`, whose real code
routes the compare through the NLS sort-table dispatch and returns
`CompareString - 2`. The sort file now *opens* (4684×/run) but kernelbase's
downstream consumption of it (section-map + `CompareString` collation) does not
yet produce a correct result, so the compare still errs. This is a deeper
NLS-emulation item, tracked as **F3**.

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
- **F3 NLS storm.** `kernelbase` re-opens `sortdefault.nls` ≈4684×/run (+ ~40
  section ops). This pass showed the re-opens are a **symptom** of the F3 bug,
  not an independent cost: kernelbase's per-locale sort load fails every compare
  (the sort registry never populates because the sort-handle build returns 0 —
  see F3), so it re-attempts the whole open→map→parse each time. Fixing F3 makes
  the load succeed **once** and the storm disappears — better than caching it.

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
the next real throughput wins are F1 (spin detection) and F3 (fixing the
locale-resolution failure, which also ends the `sortdefault.nls` re-open storm),
not more micro-optimisation here.**

### F3 — Injected-library false positive (residual: NLS collation)

**Status:** the environment/API prerequisites are fixed (`2f6e5ae`, above) —
`QueryDosDevice` resolves, `GetProcessImageFileName` is coherent, and the sort
table now opens. The false positive itself remains.

**Symptom:** al-khaser's DLL-injection check still flags **every** legitimate
module + the sample's own exe as "injected".

**Root cause — traced ~10 layers into real `kernelbase` (this pass, corrects the
earlier "collation returns wrong order" guess).** The earlier note said the
collation "errs and the `-2` becomes non-zero". That is wrong: instrumentation
(capture `StrCmpNIW`/`StrCmpIW` entry args + the return at the caller's return
address, file-based so it survives `-s`) shows the return is a **constant**
`0xFFFFFFFE` (`-2`) for **every** call — equal *and* unequal inputs alike:

```
StrCmpIW  cnt=0  rax=-2 eqBytes=True  s1="\Device\HarddiskVolume1"  s2="\Device\HarddiskVolume1"
StrCmpNIW cnt=20 rax=-2 eqBytes=True  s1="C:\Windows\System32\"     s2="C:\Windows\System32\"
StrCmpIW  cnt=0  rax=-2 eqBytes=False s1="\Device\HarddiskVolume1"  s2="C:\Users"
```

`kernelbase!StrCmpNIW` is `CompareStringW(...) - 2` — a constant `-2` means
**`CompareStringW` returns `0` (its error return) on every call**. Watching
`kernelbase` RVAs at runtime (against the shipped `kernelbase.dll`, imagebase
`0x180000000`) pins the failure precisely:

- `StrCmpNIW` (RVA `0x24ca0`): FUNC A `0x22f90` (sort-handle getter) **succeeds**
  (returns a handle), but FUNC C `0x21fa0` **returns 0** → the error path
  `0x24d4d` runs `SetLastError(ERROR_INVALID_PARAMETER 0x57)` and returns `-2`.
- FUNC C `0x21fa0` hashes the locale name and looks it up in kernelbase's
  per-locale **sort registry** (128-bucket hash table at `.data` `0x28d2a0`).
  On a miss it lazily loads the locale's sort data via `0x400401f8` and inserts
  it — this lazy load is what re-opens `sortdefault.nls` every compare (the
  ≈4684×/run storm). The registry is observed **empty** (`0/128` buckets).
- On the registry miss, FUNC C calls the per-locale sort loader `0x400401f8`.
  Its first step resolves the locale name via `0x1b4f0("en-US")`, which
  **succeeds** — `en-US` **is** in kernelbase's locale table (`[0x28e1f0]`, a
  128-bucket chained hash, `next`@`+0x58`, name@`+0x18`); `en-US` sits at its
  correct bucket (hash `0x1cbe0("en-US") = 0`), and the resolver's ASCII
  case-fold compare of the two byte-identical `en-US` strings reaches the FOUND
  path `0x1b5de`. (NB: an earlier revision of this note claimed the resolver
  "returns NULL for en-US" — that was a **diagnostic bug**, not real: the
  per-instruction hook fires *before* the watched instruction executes, so
  reading `rdi` at `mov rdi, rax` (loader `0x40223`) captured the pre-assignment
  value `0`. Reading the source `rax`, or `rdi` one instruction later, shows the
  resolver returns the real `en-US` entry. The locale table holds only ~4
  lazily-inserted entries, not "hundreds" — that count was over-reading past the
  128-bucket array.)
- The loader fails **one step below** name resolution: it calls a function
  pointer through kernelbase's CFG-dispatch thunk (`0x929f0` = `jmp rax`,
  imported via the `[0x1c0af0]` apiset self-thunk), and **that call returns 0**.
  The runtime target resolves (through the sort-init function-pointer table) to
  `kernel32!SortGetHandle` (RVA `0xa190`). So the failing step is the per-locale
  **sort-data build / sort-handle acquisition**, not the locale-name lookup and
  not the collation arithmetic. `SortGetHandle` returning 0 → the loader returns
  0 → the sort registry never populates → FUNC C returns 0 → `CompareStringW`
  = 0 → `StrCmpNIW`/`StrCmpIW` = `-2` for every input.

So the FP bottoms out in kernelbase's **sort-versioning / sort-handle build**
(the `SortGetHandle`-family called from the per-locale loader returns 0), which
cascades into every case-insensitive `CompareStringW`/`StrCmpI*`/`lstrcmpi`/CRT
compare returning error.

**Recommended approach (next pass).** Continue one layer down from
`kernel32!SortGetHandle` (RVA `0xa190`, likely forwarding to the kernelbase
sort-versioning worker): trace *its* return-0 branch — it reads the sort
version/handle table that is seeded from `sortdefault.nls`, so verify the
version fields kernelbase validates against the shipped `sortdefault.nls`
header (build mismatch: the shipped `kernelbase.dll` is a 2021 build while
`ntdll`/`kernel32` are 19041.x — a sort-version constant baked into one but not
the other would make the handle build reject). **Method note that cost this
pass:** the per-instruction hook fires *before* the instruction runs, so to
read a call's result, watch the return address and read `rax` (or the
destination one instruction later) — never read the destination register *at*
the `mov dst, rax`. Alternatively, since Brovan runs real `kernelbase` with
interception only at the **syscall** boundary (no user-mode export hook exists),
a "short-circuit `CompareStringW`/`SortGetHandle`" fix would require building an
export-interception mechanism first — larger than fixing the data path. This is
broad (all case-insensitive kernelbase collation is affected) and wants its own
pass with regression coverage. The ~10-layer trace above is the map; all
diagnostic instrumentation was reverted (tree stays clean).

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
