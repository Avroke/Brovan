using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowLongPtr : IWinSyscall
    {
        private const int GWLP_WNDPROC = -4;
        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;
        private const uint WS_VISIBLE = 0x10000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            int Index = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            ulong Value = Instance.WinHelper.GetArg64(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous;
            switch (Index)
            {
                case GWLP_WNDPROC:
                    Previous = Window.WndProc;
                    Window.WndProc = Value;
                    Instance.WinHelper.MaterializeUserWindow(Window);
                    break;

                case GWL_STYLE:
                    Previous = Window.Style;
                    Window.Style = unchecked((uint)Value);

                    bool WasVisible = (Previous & WS_VISIBLE) != 0;
                    bool NowVisible = (Window.Style & WS_VISIBLE) != 0;
                    if (WasVisible != NowVisible)
                    {
                        Window.Visible = NowVisible;
                        Window.Dirty = true;
                        Instance.WinHelper.PresentDesktop();
                    }
                    break;

                case GWL_EXSTYLE:
                    Previous = Window.ExStyle;
                    Window.ExStyle = unchecked((uint)Value);
                    break;

                default:
                    Window.WindowLongs.TryGetValue(Index, out Previous);
                    Window.WindowLongs[Index] = Value;
                    break;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
