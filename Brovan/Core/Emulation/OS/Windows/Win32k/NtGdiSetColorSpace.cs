using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSetColorSpace : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hdc = Instance.WinHelper.GetArg64(0);
            ulong ColorSpace = Instance.WinHelper.GetArg64(1);

            ulong Previous = Win32kHelper.SetDcColorSpace(Instance, Hdc, ColorSpace);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
