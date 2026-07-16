# SEH/WER dispatch — dbghelp module-list detection (investigation handoff)

**Status: OPEN — diagnosed, not yet root-caused. Runtime instrumentation resisted; a
static code-audit of the init-time DLL-load / LDR-bootstrap path is the recommended
next approach.** Tree is clean; nothing was committed for this investigation.

## The question (rule #7)

al-khaser's probe *"Checking if process loaded modules contains: dbghelp.dll"* was a
false detection (`BAD`). It was mitigated in commit **`996f60e`** by **not shipping
faultrep.dll** (dbghelp is only pulled in through faultrep). That commit itself flagged
the mitigation as symptom-level: *"The deeper SEH/WER-dispatch divergence (WER engaging
for a handled exception, then continuing) is tracked separately."*

The open question: is the faultrep-removal **masking a real SEH/WER-dispatch bug**
(handled exception spuriously engaging WER), or is it actually **correct clean-process
behaviour** (a real clean Win10 process has no faultrep/dbghelp loaded)?

## Confirmed this session (solid)

1. **Masking is load-bearing.** With faultrep restored to the runtime WindowsLibs, the
   dbghelp probe is **BAD**; removed, it is **GOOD**. (faultrep.dll is available at
   `/home/user/deps2/WindowsLibs/faultrep.dll` for reproduction.)
2. **dbghelp is a STATIC import of faultrep** (verified by parsing faultrep.dll's import
   directory — it is in the regular imports, not the delay-import directory). So avoiding
   dbghelp requires avoiding the faultrep load entirely; there is no delay-load lever.
3. **faultrep is NOT a startup static dependency of kernel32.** kernel32 imports only the
   *core* errorhandling ApiSets (`api-ms-win-core-errorhandling-l1-1-0/-l1-1-3`), which
   resolve to KERNELBASE (`BinaryEmulatorHelper.cs:662`), NOT the `ext-ms-win-kernel32-
   errorhandling` set that hosts faultrep. So faultrep is not pulled as a hard startup dep
   of kernel32.
4. **`ApiSetOverrideMap` is DEAD CODE.** The override `ext-ms-win-kernel32-errorhandling
   -l1-1-0 (importer kernel32) -> faultrep.dll` at `BinaryEmulatorHelper.cs:1463-1470` is
   **never consumed anywhere** (grep for `ApiSetOverrideMap` returns only its definition).
   It is not the mechanism. (The general schema `BinaryEmulatorHelper.cs:1177` maps that
   contract to KERNEL32, not faultrep.)
5. **al-khaser's `UnhandledExcepFilterTest` probe is GOOD** — its `SetUnhandled
   ExceptionFilter` callback IS invoked and the process survives, so that exception is
   effectively *handled* (filter presumably returns `EXCEPTION_CONTINUE_EXECUTION`). If
   WER were correctly gated, `WerpReportFault` (which pulls faultrep) would not run.

## The finding that blocks a clean root-cause

Instrumented **9 layers** — `AddModule` (`WinSyscallsHelper.cs:2264`), `NtOpenFile`,
`NtCreateFile`, and the host-side `GeneralHelper.IO.ReadFile` (`GeneralHelper.cs:2220`) —
all **env-gated on `BROVAN_WERDBG`, now fully reverted**. **Every one missed the faultrep
load**, yet dbghelp is in the guest LDR (probe BAD with faultrep present). Notes:

- `AddModule` sees only **2 modules** (`al-khaser_x64.exe`, `ntdll.dll`) — it is NOT the
  path most DLLs register through. The module list al-khaser walks is **synced from the
  guest's real PEB LDR** (`WinInternalHelper.cs:750-786`, from `LastSnapshot`).
- No `NtCreateFile`/`NtOpenFile` fires for `faultrep`/`dbghelp` (nor for other DLLs — DLL
  loading does **not** go through the guest file syscalls).
- No host-side `ReadFile` fires for `faultrep`/`dbghelp`.

**Conclusion:** faultrep/dbghelp are never read from disk *during al-khaser's run*, yet
they are in the LDR. This points to an **init-time pre-population / cached load**, not a
runtime WER file-load — which partly **contradicts commit 996f60e's "runtime WER
LoadLibrary(faultrep)" premise**.

## Reframe (matters for the rule-#7 verdict)

If the mechanism is init-time LDR pre-population (Brovan processes WindowsLibs DLLs / the
import graph and creates LDR entries for faultrep + its static import dbghelp), then the
faultrep-removal is **not masking a WER-dispatch bug** — it is correcting the set of
pre-listed modules to match a clean process (where faultrep/dbghelp are not loaded). That
would make the current fix **more defensible** than the commit's own self-critique.
But this cannot be asserted without locating the mechanism.

## The one unhooked path + recommended next step

The only DLL-read path NOT instrumented is the **`new BinaryFile(path, true)` ctor**, used
at init to read DLLs directly (e.g. ntdll at `BinaryEmulatorHelper.cs:1635`), bypassing
`GeneralHelper.IO.ReadFile`. faultrep is most likely read there, at init.

**Recommended next approach — static code audit (not more runtime instrumentation):**
1. Read the init-time DLL-load / LDR-bootstrap path: the `BinaryFile` ctor callers, and how
   the initial guest module graph is resolved and written into the guest PEB LDR
   (`WindowsGuest.cs` module setup around `:138`/`:239`; `WinInternalHelper.cs:750-786`
   LDR snapshot sync; `GeneralHelper.cs:3029` `EnsureWindowsLibsIndex`).
2. Determine whether faultrep is pulled by **transitive import-graph resolution at init**
   (which importer references the `ext-ms-win-kernel32-errorhandling`/faultrep contract?
   check KERNELBASE.dll's imports — it was absent from `deps2`, get it from the runtime
   `Brovan/bin/Release/net8.0/WindowsLibs/`), vs a **runtime WER path** after all.
3. If init-time: confirm the fix is correct clean-process behaviour and update
   `AL_KHASER_EMULATION.md` + the `Export-BrovanDeps.ps1:127-139` note to drop the
   "masking / WER-dispatch" framing. If runtime WER: pinpoint the `WerpReportFault`
   gating divergence (needs al-khaser's exact `SetUnhandledExceptionFilter` filter return
   — the source file 404'd at `al-khaser/AntiDebug/SetUnhandledExceptionFilter.cpp`; find
   the correct path in `ayoubfaouzi/al-khaser`).

## Reproduction quick-reference

- Restore faultrep: `cp /home/user/deps2/WindowsLibs/faultrep.dll Brovan/bin/Release/net8.0/WindowsLibs/`
  (and `.../SysWOW64/`). Remove it to restore the committed (GOOD) state.
- Run: `dotnet Brovan/bin/Release/net8.0/Brovan.dll --silent <VirtualFS .../Desktop/al-khaser_x64.exe>`
  (dotnet at `/home/user/.dotnet9`, `DOTNET_ROLL_FORWARD=Major`). The dbghelp probe is
  reached fast (~20-40 s, ~line 69 of al-khaser stdout: *"contains: dbghelp.dll"*).
- The `AL_KHASER_EMULATION.md` "RESOLVED" section documents the broader al-khaser context
  (48 -> 251 GOOD; the residual BAD probes).
