using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserDeleteMenu : IWinSyscall
    {
        private const uint MF_BYPOSITION = 0x00000400;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong MenuHandle = Instance.WinHelper.GetArg64(0);
            uint Position = (uint)Instance.WinHelper.GetArg64(1, true);
            uint Flags = (uint)Instance.WinHelper.GetArg64(2, true);

            WinMenu Menu = Instance.WinHelper.GetMenu(MenuHandle);
            if (Menu == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_MENU_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            int Index;
            if ((Flags & MF_BYPOSITION) != 0)
            {
                Index = Position < (uint)Menu.Items.Count ? (int)Position : -1;
            }
            else
            {
                Index = Menu.Items.FindIndex(Item => Item.Id == Position);
            }

            if (Index < 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_MENU_ITEM_NOT_FOUND);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinMenuItem Removed = Menu.Items[Index];
            Menu.Items.RemoveAt(Index);

            if (Menu.IsSystemMenu && Removed.Id != 0)
            {
                WinWindow OwnerWindow = Instance.WinHelper.GetWindow(Menu.OwnerHwnd);
                Instance.WinHelper.ReflectSystemMenuRemoval(OwnerWindow, Removed.Id);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
