using static Brovan.Core.Helpers.BinaryHelpers;
namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Cursor = Instance.WinHelper.GetArg64(0);

            ulong Previous = Win32kHelper.SetCursor(Instance, Cursor);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
