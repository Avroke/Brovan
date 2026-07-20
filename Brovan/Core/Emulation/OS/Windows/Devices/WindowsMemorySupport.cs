namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class WindowsMemorySupport
    {
        internal const ulong PageSize = 4096;
        internal const uint TotalPhysicalPages = 0x200000;                          // * 4 KiB = 8 GiB
        internal const ulong TotalPhysicalBytes = (ulong)TotalPhysicalPages * PageSize;

        internal const ulong AvailablePhysicalBytes = 0x148000000UL;               // ~5.13 GiB free
        internal const long ResidentAvailableBytes = 0x180000000L;                 // ~6 GiB
        internal const ulong CommittedBytes = 0xB0000000UL;                        // ~2.75 GiB in use
        internal const ulong SharedCommittedBytes = 0x18000000UL;                  // ~384 MiB shared
        internal const ulong CommitLimitBytes = 0x300000000UL;                     // 12 GiB (8 RAM + 4 pagefile)
        internal const ulong PeakCommitmentBytes = 0xD0000000UL;                   // ~3.25 GiB peak
    }
}
