using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetSystemMenu : IWinSyscall
    {
        private const uint WS_MINIMIZEBOX = 0x00020000;
        private const uint WS_MAXIMIZEBOX = 0x00010000;
        private const uint WS_THICKFRAME = 0x00040000;

        private const uint MF_STRING = 0x00000000;
        private const uint MF_SEPARATOR = 0x00000800;
        private const uint MF_GRAYED = 0x00000001;

        private const uint SC_RESTORE = 0xF120;
        private const uint SC_MOVE = 0xF010;
        private const uint SC_SIZE = 0xF000;
        private const uint SC_MINIMIZE = 0xF020;
        private const uint SC_MAXIMIZE = 0xF030;
        private const uint SC_CLOSE = 0xF060;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            bool bRevert = Instance.WinHelper.GetArg64(1, true) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (bRevert)
            {
                if (Window.SystemMenuHandle != 0)
                {
                    Instance.WinHelper.DestroyMenu(Window.SystemMenuHandle);
                    Window.SystemMenuHandle = 0;
                }

                Instance.WinHelper.ReflectSystemMenuReset(Window);

                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Window.SystemMenuHandle == 0 || Instance.WinHelper.GetMenu(Window.SystemMenuHandle) == null)
            {
                WinMenu Menu = new WinMenu { OwnerHwnd = Hwnd, IsSystemMenu = true };
                PopulateDefaultItems(Menu, Window);
                Window.SystemMenuHandle = Instance.WinHelper.RegisterMenu(Menu);
            }

            Instance.SetRawSyscallReturn(Window.SystemMenuHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void PopulateDefaultItems(WinMenu Menu, WinWindow Window)
        {
            bool Sizable = (Window.Style & WS_THICKFRAME) != 0;
            bool CanMinimize = (Window.Style & WS_MINIMIZEBOX) != 0;
            bool CanMaximize = (Window.Style & WS_MAXIMIZEBOX) != 0;
            bool Restorable = Window.Maximized || Window.Minimized;

            Menu.Items.Add(new WinMenuItem { Id = SC_RESTORE, Text = "&Restore", Flags = MF_STRING | (Restorable ? 0u : MF_GRAYED) });
            Menu.Items.Add(new WinMenuItem { Id = SC_MOVE, Text = "&Move", Flags = MF_STRING | (Window.Maximized ? MF_GRAYED : 0u) });

            if (Sizable)
                Menu.Items.Add(new WinMenuItem { Id = SC_SIZE, Text = "&Size", Flags = MF_STRING | (Restorable ? MF_GRAYED : 0u) });
            if (CanMinimize)
                Menu.Items.Add(new WinMenuItem { Id = SC_MINIMIZE, Text = "Mi&nimize", Flags = MF_STRING });
            if (CanMaximize)
                Menu.Items.Add(new WinMenuItem { Id = SC_MAXIMIZE, Text = "Ma&ximize", Flags = MF_STRING });

            Menu.Items.Add(new WinMenuItem { Id = 0, Text = null, Flags = MF_SEPARATOR });
            Menu.Items.Add(new WinMenuItem { Id = SC_CLOSE, Text = "&Close\tAlt+F4", Flags = MF_STRING });
        }
    }
}
