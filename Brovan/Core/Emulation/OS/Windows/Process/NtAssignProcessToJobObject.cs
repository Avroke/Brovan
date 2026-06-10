using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAssignProcessToJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandle = Instance.WinHelper.GetArg64(0);
                ulong ProcessHandle = Instance.WinHelper.GetArg64(1);
                return Instance.WinHelper.AssignProcessToJobHandle(JobHandle, ProcessHandle);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            uint JobHandle32 = Instance.ReadMemoryUInt(SP + 4);
            uint ProcessHandle32 = Instance.ReadMemoryUInt(SP + 8);
            return Instance.WinHelper.AssignProcessToJobHandle(JobHandle32, ProcessHandle32);
        }
    }
}
