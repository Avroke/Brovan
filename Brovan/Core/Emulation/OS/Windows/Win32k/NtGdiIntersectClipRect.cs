using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiIntersectClipRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.WinHelper.GetArg64(0);
            int Left = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            int Top = unchecked((int)Instance.WinHelper.GetArg64(2, true));
            int Right = unchecked((int)Instance.WinHelper.GetArg64(3, true));
            int Bottom = unchecked((int)Instance.WinHelper.GetArg64(4, true));

            ulong Result = (Left < Right && Top < Bottom) ? 1ul : 3ul;
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
