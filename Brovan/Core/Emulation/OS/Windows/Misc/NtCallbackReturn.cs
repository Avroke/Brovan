using static Brovan.Core.Helpers.BinaryHelpers;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCallbackReturn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ResultAddress = Instance.WinHelper.GetArg64(0);
            uint ResultLength = (uint)Instance.WinHelper.GetArg64(1, true);
            NTSTATUS Status = (NTSTATUS)Instance.WinHelper.GetArg64(2, true);

            bool Completed = Instance.WinHelper.CompleteUserCallback(ResultAddress, ResultLength);
            if (!Completed)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
