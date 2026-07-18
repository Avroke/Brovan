using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtSystemDebugControl (SSN 0x1BD on 19041/19044). Anti-analysis code calls it (via the
    /// SysDbg* command family) to detect a kernel debugger. On a normal system with no
    /// kernel debugger attached the service reports STATUS_DEBUGGER_INACTIVE, which
    /// al-khaser and friends read as "not detected" -- the same clean answer Brovan already
    /// returns from NtQueryDebugFilterState. Leaving it STATUS_NOT_SUPPORTED is a tell.
    /// </summary>
    internal class NtSystemDebugControl : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Command = Instance.WinHelper.GetArg64(0);
            ulong InputBuffer = Instance.WinHelper.GetArg64(1);
            uint InputBufferLength = (uint)Instance.WinHelper.GetArg64(2);
            ulong OutputBuffer = Instance.WinHelper.GetArg64(3);
            uint OutputBufferLength = (uint)Instance.WinHelper.GetArg64(4);
            ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(5);
            _ = Command;

            if (InputBufferLength != 0 && (InputBuffer == 0 || !Instance.IsRegionMapped(InputBuffer, InputBufferLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (OutputBufferLength != 0 && (OutputBuffer == 0 || !Instance.IsRegionMapped(OutputBuffer, OutputBufferLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                Instance._emulator.WriteMemory(ReturnLengthPtr, 0u, 4);

            return NTSTATUS.STATUS_DEBUGGER_INACTIVE;
        }
    }
}
