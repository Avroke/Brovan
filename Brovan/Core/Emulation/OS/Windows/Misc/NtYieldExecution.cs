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

            bool Wow64 = Instance.BackendMode == Mode.MODE_32;
            if (!Wow64)
                Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip + 2);

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

            if (Wow64)
                Instance._emulator.WriteRegister(Instance.IPRegister, SyscallRip);

            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
