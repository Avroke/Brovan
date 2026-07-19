using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtYieldExecution : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Thread, true);

            // Syscall-return EIP is bitness-asymmetric. On x64 the `syscall` INSN hook does NOT auto-advance
            // RIP, so the handler steps past the 2-byte instruction itself (RIP = SyscallRip + 2). On WOW64
            // (MODE_32) the `sysenter` INSN hook auto-advances EIP by 2 after this handler returns (same
            // quirk NtRaiseException compensates for) — so the handler must NOT add its own +2 or it
            // double-steps past the WOW64 return trampoline (`push edx ; ret`) and faults with 0xC0000005.
            // The net resume target is identical (SyscallRip + 2) on both. Was previously gated to x64 only
            // (returned STATUS_NOT_SUPPORTED on WOW64), which al-khaser's NtYieldExecution probe read as a
            // detection tell (BAD).
            bool Wow64 = Instance.BackendMode == Mode.MODE_32;
            if (!Wow64)
                Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip + 2);

            // NtYieldExecution returns STATUS_SUCCESS only when the scheduler actually swaps to another
            // ready-to-run thread; otherwise STATUS_NO_YIELD_PERFORMED. On a mostly-idle real Windows box the
            // vast majority of calls return NO_YIELD_PERFORMED — which al-khaser's NtYieldExecution probe
            // relies on: it counts non-NO_YIELD returns over its iterations and treats an excess as evidence
            // the scheduler is being manipulated. Yield to any other Ready thread if one exists; otherwise
            // report no-yield, matching real bare-metal behaviour.
            bool OtherReady = false;
            foreach (EmulatedThread Other in Instance.Threads.Values)
            {
                if (Other == null || ReferenceEquals(Other, Thread))
                    continue;
                if (Other.State == EmulatedThreadState.Ready)
                {
                    OtherReady = true;
                    break;
                }
            }

            if (!OtherReady)
                return NTSTATUS.STATUS_NO_YIELD_PERFORMED;

            // A real yield: mark ready and reschedule. Resume must land AFTER the syscall (the yield
            // completed — it must not re-execute). On x64 RIP was already advanced to SyscallRip + 2 above;
            // on WOW64 set EIP = SyscallRip so the post-return sysenter auto-advance brings it to + 2.
            if (Wow64)
                Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip);

            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
