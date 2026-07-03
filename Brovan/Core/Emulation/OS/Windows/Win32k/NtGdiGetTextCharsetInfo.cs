using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextCharsetInfo : IWinSyscall
    {
        private const uint ANSI_CHARSET = 0;
        private const int FontSignatureSize = 24;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            Instance.WinHelper.GetArg64(0);
            ulong SignaturePtr = Instance.WinHelper.GetArg64(1);
            Instance.WinHelper.GetArg64(2, true);

            if (SignaturePtr != 0 && Instance.IsRegionMapped(SignaturePtr, FontSignatureSize))
                Instance.WinHelper.WriteZeroMemory(SignaturePtr, FontSignatureSize);

            Instance.SetRawSyscallReturn(ANSI_CHARSET);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
