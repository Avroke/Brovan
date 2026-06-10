using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtIsProcessInJob : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong JobHandle = Instance.WinHelper.GetArg64(1);
                bool IsInJob = Instance.WinHelper.IsProcessInJob(ProcessHandle, JobHandle);
                return IsInJob ? NTSTATUS.STATUS_PROCESS_IN_JOB : NTSTATUS.STATUS_SUCCESS;
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            uint ProcessHandle32 = Instance.ReadMemoryUInt(SP + 4);
            uint JobHandle32 = Instance.ReadMemoryUInt(SP + 8);
            bool IsInJob32 = Instance.WinHelper.IsProcessInJob(ProcessHandle32, JobHandle32);
            return IsInJob32 ? NTSTATUS.STATUS_PROCESS_IN_JOB : NTSTATUS.STATUS_SUCCESS;
        }
    }
}
