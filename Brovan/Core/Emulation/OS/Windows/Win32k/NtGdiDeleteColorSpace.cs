using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDeleteColorSpace : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ColorSpace = Instance.WinHelper.GetArg64(0);

            bool Removed = Win32kHelper.DeleteColorSpace(Instance, ColorSpace);
            Instance.SetRawSyscallReturn(Removed ? 1u : 0u);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
