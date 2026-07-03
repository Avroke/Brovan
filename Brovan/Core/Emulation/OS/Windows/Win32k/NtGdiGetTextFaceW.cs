using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiGetTextFaceW : IWinSyscall
    {
        private const string DefaultFaceName = "MS Shell Dlg 2";

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            Instance.WinHelper.GetArg64(0);
            ulong RequestedChars = Instance.WinHelper.GetArg64(1, true);
            ulong OutBuffer = Instance.WinHelper.GetArg64(2);

            if (OutBuffer == 0 || RequestedChars == 0)
            {
                Instance.SetRawSyscallReturn((ulong)(DefaultFaceName.Length + 1));
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Written = Win32kHelper.WriteWindowText(Instance, DefaultFaceName, OutBuffer, RequestedChars, false);
            Instance.SetRawSyscallReturn(Written);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
