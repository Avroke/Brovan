using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSetIcmMode : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hdc = Instance.WinHelper.GetArg64(0);
            int Mode = unchecked((int)Instance.WinHelper.GetArg64(1, true));

            int Previous = Win32kHelper.SetDcIcmMode(Instance, Hdc, Mode);
            Instance.SetRawSyscallReturn((ulong)(uint)Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
