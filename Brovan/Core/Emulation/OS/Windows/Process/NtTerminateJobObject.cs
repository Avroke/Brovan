using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandle = Instance.WinHelper.GetArg64(0);
                return ValidateJobHandle(Instance, JobHandle);
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            uint JobHandle32 = Instance.ReadMemoryUInt(SP + 4);
            return ValidateJobHandle(Instance, JobHandle32);
        }

        private static NTSTATUS ValidateJobHandle(BinaryEmulator Instance, ulong JobHandle)
        {
            if (JobHandle == 0 || !Instance.WinHelper.HandleManager.HandleExists(JobHandle, HandleType.JobHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinJob Job = Instance.WinHelper.GetJobByHandle(JobHandle, AccessMask.GiveTemp);
            if (Job != null)
                Job.IsTerminated = true;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
