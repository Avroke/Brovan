using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtYieldExecution : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Thread, true);
            ulong NextRip = SyscallRip + 2;
            Instance._emulator.WriteRegister(Instance.IPRegister, NextRip);

            // NtYieldExecution returns STATUS_SUCCESS only when the scheduler actually swaps
            // to another ready-to-run thread; otherwise STATUS_NO_YIELD_PERFORMED. On a mostly-
            // idle real Windows box the vast majority of calls return NO_YIELD_PERFORMED — which
            // al-khaser's NtYieldExecution debugger probe relies on: it counts non-NO_YIELD
            // returns over 20 iterations and treats >3 as evidence the scheduler is being
            // manipulated. Yield to any other Ready thread if one exists; otherwise report
            // no-yield, matching real bare-metal behaviour.
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

            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
