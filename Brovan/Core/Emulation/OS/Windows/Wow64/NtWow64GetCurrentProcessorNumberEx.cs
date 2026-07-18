using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// WOW64 equivalent of <c>NtGetCurrentProcessorNumberEx(OUT PPROCESSOR_NUMBER)</c> — reports which
    /// scheduler group / processor the current thread is bound to. <c>PROCESSOR_NUMBER</c> is 4 bytes on
    /// every bitness (Group WORD, Number BYTE, Reserved BYTE), so the WOW64 form is identical to the x64
    /// form except the pointer is 32-bit. On a real x64 WOW64 host the transition dispatches straight into
    /// the shared kernel implementation; on Brovan the single scheduler group / single logical processor
    /// model is a stable answer that combase / kernelbase use only for cache-line steering, so returning a
    /// constant Group=0 Number=0 is faithful to what a 1-CPU sandbox would report.
    /// </summary>
    internal class NtWow64GetCurrentProcessorNumberEx : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessorNumberPtr = Instance.WinHelper.GetArg64(0);
            if (ProcessorNumberPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            if (!Instance.IsRegionMapped(ProcessorNumberPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            // Group=0, Number=0, Reserved=0 — one scheduler group, one active core, matches the CPUID /
            // GetLogicalProcessorInformation surface (any drift would let a sample cross-check them).
            Instance._emulator.WriteMemory(ProcessorNumberPtr, 0u, 4);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
