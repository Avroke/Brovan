using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateColorSpace : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            Instance.WinHelper.GetArg64(0);

            ulong ColorSpace = Win32kHelper.CreateColorSpace(Instance);
            Instance.SetRawSyscallReturn(ColorSpace);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
