using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiDeleteObjectApp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Handle = Instance.WinHelper.GetArg64(0);
            bool Deleted = Instance.WinHelper.FreeGdiHandle(Handle);
            Instance.SetRawSyscallReturn(Deleted ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
