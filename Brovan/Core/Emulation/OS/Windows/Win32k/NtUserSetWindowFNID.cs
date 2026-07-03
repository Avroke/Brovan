using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowFNID : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ushort Fnid = (ushort)Instance.WinHelper.GetArg64(1, true);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.WindowFNID = Fnid;
            Instance.WinHelper.MaterializeUserWindow(Window);
            Instance.WinHelper.GetUserWindowClientAddress(Window);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
