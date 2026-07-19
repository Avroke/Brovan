using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEndPaint : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            ulong PaintStructPtr = Instance.WinHelper.GetArg64(1);

            if (Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // PAINTSTRUCT.hdc is the first field — pointer-sized (4 on x86, 8 on x64).
            if (PaintStructPtr != 0 && Instance.IsRegionMapped(PaintStructPtr, (ulong)Instance.GuestPointerSize))
            {
                ulong Hdc = Instance.ReadPointer(PaintStructPtr);
                Win32kHelper.ReleaseDeviceContext(Instance, Hdc);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
