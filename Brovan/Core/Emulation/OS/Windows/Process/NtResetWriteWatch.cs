using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtResetWriteWatch (SSN 0x179 on 19041/19044). Backs kernel32/kernelbase's
    /// <c>ResetWriteWatch</c>: clears the recorded write set for a MEM_WRITE_WATCH region so a
    /// subsequent NtGetWriteWatch starts from a clean slate.
    ///
    /// <code>
    /// NTSTATUS NtResetWriteWatch(
    ///   HANDLE ProcessHandle,   // arg0
    ///   PVOID  BaseAddress,     // arg1
    ///   SIZE_T RegionSize)      // arg2
    /// </code>
    ///
    /// al-khaser's write-watch "code write" probe relies on this: it writes generated code into
    /// the watched buffer (dirtying it), resets, runs the code, then expects a zero hit-count.
    /// </summary>
    internal class NtResetWriteWatch : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong BaseAddress = Instance.WinHelper.GetArg64(1);
            ulong RegionSize = Instance.WinHelper.GetArg64(2);

            if (ProcessHandle != ulong.MaxValue)
            {
                if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinProcess Proc = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMOperation);
                if (Proc == null || Proc.PID != Instance.WinHelper.PID)
                    return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (BaseAddress == 0 || RegionSize == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Non-zero (STATUS_INVALID_PARAMETER) when the range is not a MEM_WRITE_WATCH region,
            // matching kernel32's ResetWriteWatch returning a non-zero failure.
            if (Instance.WriteWatch == null || !Instance.WriteWatch.Reset(BaseAddress, RegionSize))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
