# faultrep/dbghelp module-list detection — RESOLVED (it was never SEH/WER)

**Status: RESOLVED.** The al-khaser *"process loaded modules contains: dbghelp.dll"*
false detection was **not** an SEH/WER-dispatch bug at all. Runtime tracing proved
faultrep.dll (and its static import dbghelp.dll) were dragged into every emulated process
**at load time by a bogus ApiSet override**, with zero exceptions involved. The override was
removed; the contract now resolves to KERNELBASE (matching real Windows), so faultrep ships
on disk (a file-existence probe passes) but is never loaded. The earlier symptom-level
mitigation — not shipping faultrep.dll (commit `996f60e`) — is reverted.

## Root cause (runtime-proven, not inferred)

`Brovan/Core/Emulation/BinaryEmulatorHelper.cs` carried an `ApiSetOverrideMap` entry:

```
ext-ms-win-kernel32-errorhandling-l1-1-0.dll  (importer kernel32.dll)  ->  faultrep.dll
```

`CrossGenerator.GenerateMap()` (`GeneralHelper.cs:3077`) bakes this override into the
synthetic ApiSet schema (`apisetmap.bin`) that the **real guest ntdll loader** consumes
(there is no `apisetschema.dll` on disk, so Brovan supplies the schema). **kernelbase.dll
imports `ext-ms-win-kernel32-errorhandling-l1-1-0`** (via delay-load — dir[13] — see the
audit section below), the override resolved the contract to faultrep, and Brovan bound that
import at process-load time, so the loader mapped faultrep.dll → which statically imports
dbghelp.dll → both land in the PEB LDR. al-khaser walks the LDR
(`LdrEnumerateLoadedModules`) and flags dbghelp.

The override was wrong for this emulator's goal: pointing the contract at faultrep force-loads
faultrep + dbghelp into every process, whereas on a real clean Win10 box the delay import
never fires and neither DLL is resident. (Strictly, this contract *does* host faultrep's
`BasepReportFault` / `CheckForReadOnlyResourceFilter`; resolving it to KERNELBASE is the
pragmatic fix — see "AUDIT 4" below for the full nuance.)

## The fix

1. **Remove the override** and map the contract to KERNELBASE in `ApiSetMap`
   (`ext-ms-win-kernel32-errorhandling-l1-1-0 → KERNELBASE.dll`). The contract now binds to
   already-resident kernelbase, so Brovan's eager resolution of the import maps no new module
   — faultrep is never pulled.
2. **Completed the WER apiset mappings** as a related correctness fix: the schema had only
   `api-ms-win-core-windowserrorreporting-l1-1-3 → KERNELBASE`, but kernel32 statically
   imports `-l1-1-0/1/2/3`; all their functions are KERNELBASE exports, so all four now map
   to KERNELBASE.
3. **Reverted the masking** (`996f60e`): `faultrep` is back in the curated dep set
   (`Export-BrovanDeps.ps1`) and the `Import-BrovanDeps.{ps1,sh}` strip-blocks are removed,
   so faultrep.dll ships on disk again — a file-existence probe passes, and with the apiset
   fixed it stays unloaded.

**Validation** (al-khaser_x64, faultrep.dll present on disk):
- dbghelp probe: **BAD → GOOD**; guest healthy through the module / VM-detection / timing
  sections (same ~296-line endpoint as before, no new early termination).
- In-session A/B at the identical truncation point: baseline (faultrep loading) 249 GOOD /
  6 BAD → fixed 250 GOOD / 5 BAD. Exactly one probe moved (dbghelp); no regression.
- Instrumented trace confirmed 0 faultrep/dbghelp map events after the fix.

## How the earlier "SEH/WER" framings were wrong

- Commit `996f60e` blamed *"the CRT/WER unhandled-exception path
  (ucrtbase!_seh_filter_exe) LoadLibrary(faultrep) during al-khaser's
  SetUnhandledExceptionFilter self-test"*. Runtime tracing at the image-map chokepoint
  (`NtMapViewOfSection → LoadBinary`) showed faultrep maps **at process init**, from a pure
  ntdll `Ldrp*` loader call chain, with **no exception dispatched before it** (an
  exception-dispatch trace recorded 0 exceptions prior to the map). Not a WER path.
- A prior handoff draft of this doc concluded the removal was *"masking a runtime
  WER-dispatch divergence"* and proposed fixing a `WerpReportFault` gate. Also wrong —
  Brovan does not reimplement the SEH/UEF/WER decision (it delivers a faithful
  `KiUserExceptionDispatcher` frame and the real guest DLLs decide); and no exception was
  involved here at all. The `KERNELBASE+0x273C80` "frame" that briefly looked like a WER
  caller was a `.rdata` data pointer on the stack (false positive), not a return address.

## Debugging notes (for future apiset work)

- The generated schema is **cached** to `bin/.../apisetmap.bin` and only regenerated when
  absent (`Program.cs:256`). After editing `ApiSetMap`/`ApiSetOverrideMap` you **must delete
  `apisetmap.bin`** or the guest keeps using the stale schema. (Two experiments were
  invalidated by this before it was noticed.)
- Brovan logs `LoadBinary` / exception dispatch via `LogFlags.General`, which `--silent`
  suppresses — route ad-hoc traces to a file, not `TriggerEventMessage`, when running
  `--silent`.
- The al-khaser run under Brovan consistently ends at ~line 296 (the SetTimer timing
  section) for this profile; that truncation is pre-existing and unrelated to this fix.

## Follow-up: systematic ApiSet audit (are there other bad overrides / bad contracts?)

A static audit cross-checked every apiset contract each WindowsLibs DLL imports against
Brovan's `ApiSetMap` + `ApiSetOverrideMap` and the resolved host's real export table.
Matching uses Brovan's hash key (strip the last `-<digit>` once, per
`ComputeHashedLengthBytes`), so a `…-l1-1-3` entry already covers `…-l1-1-0/1/2`.

- **Conflicting hosts (same hash key → >1 distinct host):** none.
- **Bad overrides (override host lacks the importer's functions):** none remaining — the
  faultrep override was the only one; every other override
  (appinit/io/processsecurity/processthreads/util → KERNELBASE for kernel32) checks out.
- **Missing contracts (imported, no schema entry):** 13, all `ext-ms-win-*` **extension**
  apisets (knownfolderext, defaultdiscovery, win32-subsystem-query, containers-policymanager,
  appmodel-deployment, security-authz-helper, oobe-query, winrt-remote, com-apartmentrestriction,
  com-suspendresiliency, appmodel-viewscalefactor, windowscore-deviceinfo, security-chambers).
  These are optional/empty on a real Win10 client; because they map to **nothing** they cannot
  drag a wrong DLL in (not the faultrep class). The importing DLLs (combase, ole32, shell32,
  windows.storage, …) all load and run fine. Minor faithfulness gap only: real Win10 carries
  them as empty-host entries; Brovan omits them. Left as-is (benign).
- **Redundant entries:** the `api-ms-win-core-windowserrorreporting-l1-1-0/1/2` entries added
  alongside `-l1-1-3` are redundant (same hash key, same host); harmless, kept.

### The one real nuance (AUDIT 4): `ext-ms-win-kernel32-errorhandling-l1-1-0`

This contract genuinely hosts **faultrep** functions — kernelbase `BasepReportFault` /
`CheckForReadOnlyResourceFilter` come from it — and kernelbase imports them via **delay-load**
(dir[13]), so on a real clean Win10 process faultrep never loads (the delay bind only fires on
an actual fault-report). Mapping the contract to KERNELBASE (the fix) points that delay import
at a host that does **not** export those two functions — strictly a "wrong host". It is the
correct *pragmatic* choice because:

- The functions are internal WER-reporting helpers, only reached on the fault-report path,
  which is a Brovan boundary anyway (WER is out-of-process on real Windows).
- A clean run never triggers the delay bind, so the host is never consulted (validated: the
  296-line al-khaser run is byte-identical healthy).
- Any resolution to faultrep (default or override) reloads it; pointing the contract at an
  already-resident DLL (kernelbase) is the only resolution that keeps the module list faithful
  and never fails a bind in practice.

### Is there a "deeper" loader bug behind this? — investigated, NO.

An earlier draft speculated that Brovan *eager-resolves* this delay import (would be a broad
loader bug). A full-map diagnostic (log every DLL the guest loader maps, `BROVAN_MAPLOG`)
disproves that:

- **Brovan does not eager-load delay imports.** combase delay-imports `clbcatq`, shcore
  delay-imports `imm32`, etc. — **none of those delay-only hosts are loaded**. The loader
  honors delay-load laziness generally.
- **The fix removes exactly the faultrep chain and nothing else.** Diffing the mapped-DLL set
  override-on (faultrep) vs fixed (KERNELBASE): the only DLLs that drop are
  `faultrep.dll → dbghelp.dll → dbgcore.dll`. Every other delay-host (gdi32full,
  windows.storage, powrprof, cfgmgr32, shcore, …) is loaded in **both** — pulled by
  al-khaser's actual GDI/shell/power calls, exactly as on real Windows.
- **faultrep was pulled by a real call, not an eager bind.** In the load order it appears at
  position ~34 — after the *entire* static-import graph, where the CRT / early al-khaser
  checks run — i.e. a genuine delay-load of `CheckForReadOnlyResourceFilter` /
  `BasepReportFault` fired. With the contract → faultrep that call loads faultrep (the tell);
  with → KERNELBASE the same call resolves to a function that is not there, the delay bind
  no-ops, and faultrep never loads.

So there is **no separate loader bug to fix**. WER / fault-reporting is a Brovan boundary by
design, so a WER-internal helper whose delay slot resolves to a no-op is the *desired*
behavior, not a defect — and the resulting module list matches a clean Win10 box exactly.
The KERNELBASE mapping is the complete and correct fix, not an interim one.
