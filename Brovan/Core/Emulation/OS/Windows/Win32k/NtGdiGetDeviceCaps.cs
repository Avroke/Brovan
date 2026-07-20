namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetDeviceCaps : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int Index = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            Instance.SetRawSyscallReturn(unchecked((ulong)(uint)GetDeviceCapability(Index)));
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static int GetDeviceCapability(int Index)
        {
            return Index switch
            {
                2 => 1,
                4 => 320,
                6 => 180,
                8 => 1920,
                10 => 1080,
                12 => 32,
                14 => 1,
                24 => -1,
                88 => 96,
                90 => 96,
                116 => 60,
                121 => 0x00000003,
                _ => 0,
            };
        }
    }
}
