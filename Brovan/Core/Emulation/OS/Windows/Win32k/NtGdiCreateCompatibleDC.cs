using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateCompatibleDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            Instance.WinHelper.GetArg64(0);

            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, 0, false, false);
            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
