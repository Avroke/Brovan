using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetDialogPointer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong DialogPointer = Instance.WinHelper.GetArg64(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous = Window.DialogPointer;
            Window.DialogPointer = DialogPointer;

            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
