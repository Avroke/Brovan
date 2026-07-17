using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtQueryTimerResolution (SSN 0x162 on 19041/19044). Reports the system timer's
    /// coarsest ("minimum"), finest ("maximum") and current interrupt period in 100-ns
    /// units. Anti-analysis code reads it to sanity-check the clock, so returning
    /// STATUS_NOT_SUPPORTED is a tell. The values are kept coherent with the 156250
    /// (15.625 ms) increment already reported by NtQuerySystemInformation.
    /// </summary>
    internal class NtQueryTimerResolution : IWinSyscall
    {
        // 100-ns units. 156250 = 15.625 ms (the default idle period, matching the
        // TimeIncrement returned by NtQuerySystemInformation); 5000 = 0.5 ms is the finest
        // period a caller can request. Idle Windows sits at the coarsest, so Current == Minimum.
        private const uint MinimumResolution = 156250;
        private const uint MaximumResolution = 5000;
        private const uint CurrentResolution = 156250;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong MinimumTimePtr = Instance.WinHelper.GetArg64(0);
            ulong MaximumTimePtr = Instance.WinHelper.GetArg64(1);
            ulong CurrentTimePtr = Instance.WinHelper.GetArg64(2);

            if (MinimumTimePtr == 0 || MaximumTimePtr == 0 || CurrentTimePtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.IsRegionMapped(MinimumTimePtr, 4) ||
                !Instance.IsRegionMapped(MaximumTimePtr, 4) ||
                !Instance.IsRegionMapped(CurrentTimePtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(MinimumTimePtr, MinimumResolution, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(MaximumTimePtr, MaximumResolution, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(CurrentTimePtr, CurrentResolution, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
