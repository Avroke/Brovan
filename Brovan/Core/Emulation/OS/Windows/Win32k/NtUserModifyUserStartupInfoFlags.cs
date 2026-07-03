using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserModifyUserStartupInfoFlags : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            // Guest does not maintain kernel-side startup flags
            _ = Instance.WinHelper.GetArg64(0, true);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
