#!/usr/bin/env python3
"""
J0 spike — go/no-go for "Voie A" (native CLR emulation of .NET PEs in Brovan).

See docs/DOTNET_NATIVE_CLR_EMULATION.md §5 / §8. The single central risk of
running the *real* CLR inside Brovan is whether the emulation backend can
faithfully execute code that is produced at run time by the JIT:

  1. runtime-written code is actually executed (not stale bytes),
  2. a page allocated RW, written, then flipped to RX (W^X JIT / the exact
     NtProtectVirtualMemory transition) executes the freshly-written bytes,
     and executing it *before* the flip faults (NX enforced),
  3. TRUE self-modifying code: a code page whose translation was already
     cached is overwritten and re-executed — the NEW bytes must run
     (translation-block invalidation). This is the tiered-recompilation /
     call-stub-backpatch case the CLR relies on.

Brovan wraps *stock Unicorn* (2.1.4 per docs/AL_KHASER_EMULATION.md) and its
UnicornBackend passes MemoryProtection (Read=1/Write=2/Execute=4, identical to
UC_PROT_*) straight to uc_mem_map / uc_mem_protect / uc_mem_write / uc_emu_start
(Core/Emulation/UnicornBinding/Unicorn.cs:182/1080/359, Backends/Unicorn/
UnicornBackend.cs). This harness drives the *same native engine version* through
the *same primitives*, so a green result here validates the engine capability
Brovan depends on. It does NOT exercise Brovan's C# syscall layer (no dotnet in
this env) — that end-to-end leg is J2+ and needs the toolchain.

KVM backend: SMC is hardware-native (real CPU), but /dev/kvm is absent here, so
the KVM leg of J0 must be re-run on a KVM-capable host. This harness is Unicorn-
only by necessity.

x86-64 throughout (.NET Framework x64 is the recommended first target, §10).
"""

import struct
import sys
from unicorn import (
    Uc, UcError, UC_ARCH_X86, UC_MODE_64,
    UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_ALL,
)
from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_RIP

# ---- fixed layout (4 KiB-aligned regions) ----------------------------------
DRIVER = 0x1000_0000   # RX  — "the JIT compiler + caller" (executing native code)
JITBUF = 0x2000_0000   # code heap — protection varies per test
SRC    = 0x3000_0000   # RW  — the JIT's internal buffer (machine code as *data*)
DATA   = 0x4000_0000   # RW  — result cells the emitted stubs write to
STACK  = 0x5000_0000   # RW
STOP   = 0x9000_0000   # 'until' sentinel (need not be mapped; emu stops before it)
PAGE   = 0x1000
RSP0   = STACK + 0xF00

R1, R2, R3 = DATA + 0x00, DATA + 0x08, DATA + 0x10   # result cells

MAGIC_A = 0x1111_2222_3333_4444
MAGIC_B = 0x5555_6666_7777_8888
MAGIC_C = 0x9999_AAAA_BBBB_CCCC


# ---- minimal x86-64 encoder (only what the stubs need) ---------------------
def mov_rax_imm64(imm):          # 48 B8 <imm64>
    return b"\x48\xB8" + struct.pack("<Q", imm & 0xFFFFFFFFFFFFFFFF)

def mov_moffs_rax(addr):         # 48 A3 <abs64>  ->  mov [addr], rax
    return b"\x48\xA3" + struct.pack("<Q", addr)

def mov_rsi_imm64(imm): return b"\x48\xBE" + struct.pack("<Q", imm)
def mov_rdi_imm64(imm): return b"\x48\xBF" + struct.pack("<Q", imm)
def mov_rcx_imm64(imm): return b"\x48\xB9" + struct.pack("<Q", imm)
REP_MOVSB = b"\xF3\xA4"
CALL_RAX  = b"\xFF\xD0"
RET       = b"\xC3"

def emit_store_stub(magic, cell):
    """A leaf 'method': write `magic` to `cell`, then ret."""
    return mov_rax_imm64(magic) + mov_moffs_rax(cell) + RET


def new_uc():
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(DRIVER, PAGE, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_map(SRC,    PAGE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(DATA,   PAGE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(STACK,  PAGE, UC_PROT_READ | UC_PROT_WRITE)
    # JITBUF mapped per-test (protection differs) — caller maps it.
    return uc

def run_from(uc, entry):
    """Push STOP as return address, run until the stub rets back to STOP."""
    uc.reg_write(UC_X86_REG_RSP, RSP0)
    uc.mem_write(RSP0, struct.pack("<Q", STOP))
    uc.emu_start(entry, STOP)

def rq(uc, cell):
    return struct.unpack("<Q", uc.mem_read(cell, 8))[0]


# ---- tests -----------------------------------------------------------------
results = []
def record(name, ok, detail):
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def t0_sanity_host_written_rwx():
    """Encodings are correct: a host-written stub on an RWX page runs."""
    uc = new_uc()
    uc.mem_map(JITBUF, PAGE, UC_PROT_ALL)
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_A, R1))
    run_from(uc, JITBUF)
    got = rq(uc, R1)
    record("T0 sanity (RWX host-written executes)",
           got == MAGIC_A, f"[R1]=0x{got:016X} (want 0x{MAGIC_A:016X})")


def t1_rw_then_rx_faithful_wx():
    """The exact NtProtectVirtualMemory JIT flip: NX enforced, then RW->RX runs."""
    uc = new_uc()
    uc.mem_map(JITBUF, PAGE, UC_PROT_READ | UC_PROT_WRITE)     # RW, no exec
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_B, R1))

    # (a) executing a non-exec page must fault (proves W^X is real, not RWX-always)
    nx_enforced = False
    try:
        run_from(uc, JITBUF)
    except UcError:
        nx_enforced = True

    # (b) flip RW->RX (what SetMemoryProtection -> uc_mem_protect does) then run
    uc.mem_protect(JITBUF, PAGE, UC_PROT_READ | UC_PROT_EXEC)
    ran_after_flip = False
    try:
        run_from(uc, JITBUF)
        ran_after_flip = (rq(uc, R1) == MAGIC_B)
    except UcError as e:
        ran_after_flip = False

    ok = nx_enforced and ran_after_flip
    record("T1 RW->RX faithful W^X",
           ok, f"NX-fault-before-flip={nx_enforced}, executed-after-flip={ran_after_flip}")


def t2_guest_emitted_code():
    """Executing guest code emits machine code into the heap, then calls it."""
    uc = new_uc()
    uc.mem_map(JITBUF, PAGE, UC_PROT_ALL)   # code heap RWX (common JIT config)

    template = emit_store_stub(MAGIC_C, R2)  # the "compiled method" as data
    uc.mem_write(SRC, template)

    driver = (
        mov_rsi_imm64(SRC)            # rsi = internal buffer
        + mov_rdi_imm64(JITBUF)       # rdi = code heap
        + mov_rcx_imm64(len(template))
        + REP_MOVSB                   # *** guest writes machine code at runtime ***
        + mov_rax_imm64(JITBUF)
        + CALL_RAX                    # *** and immediately executes it ***
        + RET
    )
    uc.mem_write(DRIVER, driver)
    run_from(uc, DRIVER)
    got = rq(uc, R2)
    record("T2 guest-emitted code executes",
           got == MAGIC_C, f"[R2]=0x{got:016X} (want 0x{MAGIC_C:016X})")


def t3a_host_overwrite_raw():
    """
    CHARACTERIZATION (not JIT-critical): a cached code page overwritten by a
    HOST-side uc_mem_write between runs. Unicorn 2.1.4 does NOT auto-invalidate
    the TCG cache on the API write path -> stale bytes re-run. This is a latent
    Brovan/Unicorn-wrapper gap (it also affects host-path-written self-modifying
    NATIVE code), independent of .NET. The JIT itself does NOT take this path
    (its code writes are guest-driven -> see T2/T3b, which pass). Mitigation is
    proven in T4. Reported as an engine caveat; does not gate the J0 verdict.
    """
    uc = new_uc()
    uc.mem_map(JITBUF, PAGE, UC_PROT_ALL)
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_A, R3))
    run_from(uc, JITBUF)                       # translate + cache TB for JITBUF
    first = rq(uc, R3)
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_B, R3))   # host overwrite, no invalidation
    run_from(uc, JITBUF)
    second = rq(uc, R3)
    stale = (first == MAGIC_A) and (second == MAGIC_A)
    # We *expect* staleness here on stock 2.1.4; report it as the known caveat.
    record("T3a host-overwrite (engine caveat, informational)",
           True, f"run2=0x{second:016X} "
                 f"({'STALE as expected -> needs remove_cache (T4)' if stale else 'invalidated'})")


def t4_host_overwrite_mitigated():
    """JIT-critical: uc_ctl_remove_cache(start,end) after a host write fixes T3a."""
    uc = new_uc()
    uc.mem_map(JITBUF, PAGE, UC_PROT_ALL)
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_A, R3))
    run_from(uc, JITBUF)
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_B, R3))
    uc.ctl_remove_cache(JITBUF, JITBUF + PAGE)   # <-- the required Brovan fix
    run_from(uc, JITBUF)
    got = rq(uc, R3)
    record("T4 host-overwrite + remove_cache (mitigation)",
           got == MAGIC_B, f"[R3]=0x{got:016X} (want 0x{MAGIC_B:016X})")


def t3b_smc_within_one_run():
    """Guest patches an already-executed code page, then re-calls it in the SAME run."""
    uc = new_uc()
    uc.mem_map(JITBUF, PAGE, UC_PROT_ALL)

    # method: write [R3]=rax(imm at JITBUF+2), ret.  We patch that imm at runtime.
    uc.mem_write(JITBUF, emit_store_stub(MAGIC_A, R3))
    # 8-byte source for the patched immediate lives in SRC (as data)
    uc.mem_write(SRC, struct.pack("<Q", MAGIC_B))

    IMM_OFF = JITBUF + 2   # offset of the imm64 inside 'mov rax, imm64'
    driver = (
        mov_rax_imm64(JITBUF) + CALL_RAX               # call v1 -> [R3]=A
        + mov_rsi_imm64(SRC) + mov_rdi_imm64(IMM_OFF)  # patch the immediate in-place
        + mov_rcx_imm64(8) + REP_MOVSB                 # *** self-modify cached code ***
        + mov_rax_imm64(JITBUF) + CALL_RAX             # call again -> must be [R3]=B
        + RET
    )
    uc.mem_write(DRIVER, driver)
    run_from(uc, DRIVER)
    got = rq(uc, R3)
    record("T3b SMC within one run (intra-run patch)",
           got == MAGIC_B, f"[R3]=0x{got:016X} (want 0x{MAGIC_B:016X})")


def main():
    import unicorn
    print(f"Unicorn engine version: {unicorn.__version__}  (Brovan targets 2.1.4)")
    print("Backend: Unicorn/TCG only (no /dev/kvm here -> KVM leg deferred to a KVM host)\n")

    # JIT-critical: these are exactly the code-production patterns the CLR JIT
    # takes (runtime emit, W^X RW->RX flip, guest-driven codegen + self-modify),
    # plus the proven mitigation for host-side overwrites. All must pass for GO.
    jit_critical = [t0_sanity_host_written_rwx, t1_rw_then_rx_faithful_wx,
                    t2_guest_emitted_code, t3b_smc_within_one_run,
                    t4_host_overwrite_mitigated]
    # Informational: characterizes the stock-engine SMC caveat (host write path).
    informational = [t3a_host_overwrite_raw]

    print("-- JIT-critical --")
    crit_pass = 0
    for t in jit_critical:
        before = len(results)
        try:
            t()
        except Exception as e:
            record(t.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")
        crit_pass += 1 if results[before][1] else 0

    print("-- engine SMC characterization (informational) --")
    for t in informational:
        try:
            t()
        except Exception as e:
            record(t.__name__, False, f"EXCEPTION {type(e).__name__}: {e}")

    print()
    verdict = ("GO (JIT execution capability validated; host-write overwrites "
               "require uc_ctl_remove_cache in Brovan's write path)"
               if crit_pass == len(jit_critical)
               else "NO-GO / needs investigation")
    print(f"==== J0 (Unicorn leg): {crit_pass}/{len(jit_critical)} JIT-critical passed -> {verdict} ====")
    return 0 if crit_pass == len(jit_critical) else 1


if __name__ == "__main__":
    sys.exit(main())
