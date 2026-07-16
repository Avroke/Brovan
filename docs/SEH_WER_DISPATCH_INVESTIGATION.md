# SEH/WER dispatch — dbghelp module-list detection (investigation handoff)

**Status: OPEN — mechanism pinned, fix not yet applied.** The static code-audit is DONE
and settles the rule-#7 verdict: the faultrep-removal **is masking a runtime WER-dispatch
divergence** (the "init-time pre-population" reframe is DISPROVEN — see "Reframe — RESOLVED"
below). What remains is a targeted runtime fix to the WER/UEF gate so a *handled* exception
never reaches `WerpReportFault`. Tree is clean; only this doc changed.

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

## Reframe — RESOLVED by static audit (the init-time hypothesis is DISPROVEN)

The previous draft floated an "init-time LDR pre-population" reframe that would have made
the faultrep-removal a *correct clean-process* fix rather than masking. **A static code
audit of the module-load / LDR path disproves it.** The mechanism is now pinned:

1. **No Brovan C# code loads faultrep.** The only three references in the whole tree are
   inert: `BinaryEmulatorHelper.cs:796` (`api-ms-win-core-windowserrorreporting-l1-1-3`
   -> KERNELBASE, schema) and `:1188` (`ext-ms-win-kernel32-windowserrorreporting-l1-1-1`
   -> KERNEL32, schema) are apiset name-map entries, not loads; `:1470` is the **dead**
   `ApiSetOverrideMap` entry (never consumed). Nothing force-loads faultrep.
2. **The guest LDR is NOT seeded with a fabricated module list.** Bootstrap maps **only
   ntdll** directly (`WindowsGuest.cs:1585` -> `LoadWinLibrary`). Every other module
   (kernel32, kernelbase, …, and faultrep) is loaded by the **real guest ntdll loader
   executing on the CPU**, which writes PEB->Ldr; Brovan's `WinModules` merely *mirrors*
   that via the LDR-snapshot walk (`WinInternalHelper.cs:737-808`). `WinModules` has
   exactly two writers — the snapshot mirror (`:786`) and `AddModule`
   (`WinSyscallsHelper.cs:2280`, fed by `LoadWinLibrary`); **neither copies the host
   process's modules nor injects a static list**. So there is no init-time pre-population
   path that could put faultrep in the LDR.
3. **Therefore faultrep can only enter the LDR via the runtime guest-loader path**
   (`NtOpenFile` -> `NtCreateSection(SEC_IMAGE, fileHandle)` -> `NtMapViewOfSection` ->
   `LoadWinLibrary`). An image section *requires* a file handle
   (`NtCreateSection.cs:43-49`), so an `NtOpenFile("…faultrep.dll")` must precede any map.
   **This means WER genuinely engages at runtime** — the faultrep-removal **IS masking a
   real SEH/WER-dispatch divergence**, exactly as commit 996f60e's own self-critique said.
   The reframe is dead; do not re-open it.

### Why the earlier 9 instrumentation points missed the load

The real image-map chokepoint is **`NtMapViewOfSection` -> `LoadBinary(SectionHostPath)`
-> `new BinaryFile(hostPath, true)`** (`NtMapViewOfSection.cs:186`,
`BinaryEmulator.WindowsBridge.cs:890`). `LoadBinary` reads the host DLL with a **direct
`BinaryFile` ctor (host `File` read), which bypasses `GeneralHelper.IO.ReadFile`** — that
is precisely why the ReadFile hook never fired. The `AddModule`-sees-2-modules observation
is consistent: most modules register through the **snapshot mirror**, not `AddModule`.
The one still-unexplained gap is that the (reverted) `NtOpenFile` hook did not fire either
— an image map cannot happen without a preceding open, so either that hook was mis-gated,
**or faultrep enters through the `NtOpenSection(\KnownDlls\…)` fallback** the loader tries
before `NtOpenFile`. Both are runtime paths; neither revives the init-time theory.

## Recommended next step (runtime, at the CORRECT chokepoint)

Root-causing the WER-dispatch divergence is now a targeted runtime task, not another broad
sweep:

1. Instrument the **confirmed image-map chokepoint** — `NtMapViewOfSection.cs:186` /
   `LoadBinary` (`BinaryEmulator.WindowsBridge.cs:890`) — plus `NtOpenSection` and (with
   correct gating this time) `NtOpenFile`. Log the mapped basename + the guest return
   address / preceding syscall. Confirm faultrep maps and capture **who calls it**
   (expected: a `Werp…`/`kernelbase` frame on the exception path).
2. With the caller pinned, find the **WER-gating divergence**: al-khaser's
   `UnhandledExcepFilterTest` is GOOD (its `SetUnhandledExceptionFilter` callback runs and
   the process survives), so on real Windows `WerpReportFault` would NOT run. Get
   al-khaser's exact filter return value (`ayoubfaouzi/al-khaser`,
   `AntiDebug/UnhandledExceptionFilter*.cpp` — the path 404'd before; locate it) and
   compare against how Brovan's SEH/UEF dispatch decides to fall through to WER.
3. Fix the gate so a *handled* exception does not reach `WerpReportFault`. Once WER no
   longer engages, faultrep/dbghelp are never loaded **as a consequence of correct
   dispatch** — at which point the faultrep-removal becomes redundant and can be dropped,
   turning the symptom-level mitigation into a real fix (satisfies rule #7).

Do NOT restore the "init-time / clean-process-correction" framing in `AL_KHASER_EMULATION.md`
or `Export-BrovanDeps.ps1:127-139` — the audit shows the current removal is a runtime-WER
mask, so that framing would be wrong.

## Reproduction quick-reference

- Restore faultrep: `cp /home/user/deps2/WindowsLibs/faultrep.dll Brovan/bin/Release/net8.0/WindowsLibs/`
  (and `.../SysWOW64/`). Remove it to restore the committed (GOOD) state.
- Run: `dotnet Brovan/bin/Release/net8.0/Brovan.dll --silent <VirtualFS .../Desktop/al-khaser_x64.exe>`
  (dotnet at `/home/user/.dotnet9`, `DOTNET_ROLL_FORWARD=Major`). The dbghelp probe is
  reached fast (~20-40 s, ~line 69 of al-khaser stdout: *"contains: dbghelp.dll"*).
- The `AL_KHASER_EMULATION.md` "RESOLVED" section documents the broader al-khaser context
  (48 -> 251 GOOD; the residual BAD probes).
