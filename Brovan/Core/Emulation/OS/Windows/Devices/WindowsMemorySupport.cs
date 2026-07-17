namespace Brovan.Core.Emulation.OS.Windows
{
    // Single source of truth for physical-RAM facts. Every surface that reports total
    // system memory — SystemBasicInformation(Ex), SystemMemoryUsageInformation (the sole
    // source modern kernelbase!GlobalMemoryStatusEx queries), GetPhysicallyInstalledSystemMemory
    // — reads from here so a sample that cross-checks RAM across paths sees one coherent
    // 8 GiB machine. A 64 GB-class disk or a sub-2 GB RAM report is a stock anti-VM tell;
    // keeping every path in agreement is the realism invariant (rule #1).
    internal static class WindowsMemorySupport
    {
        internal const ulong PageSize = 4096;
        internal const uint TotalPhysicalPages = 0x200000;                          // * 4 KiB = 8 GiB
        internal const ulong TotalPhysicalBytes = (ulong)TotalPhysicalPages * PageSize;

        // Idle-desktop steady state. The five commitment figures are internally consistent:
        // Available < Total, Committed < CommitLimit, Peak in [Committed, CommitLimit].
        internal const ulong AvailablePhysicalBytes = 0x148000000UL;               // ~5.13 GiB free
        internal const long ResidentAvailableBytes = 0x180000000L;                 // ~6 GiB
        internal const ulong CommittedBytes = 0xB0000000UL;                        // ~2.75 GiB in use
        internal const ulong SharedCommittedBytes = 0x18000000UL;                  // ~384 MiB shared
        internal const ulong CommitLimitBytes = 0x300000000UL;                     // 12 GiB (8 RAM + 4 pagefile)
        internal const ulong PeakCommitmentBytes = 0xD0000000UL;                   // ~3.25 GiB peak
    }
}
