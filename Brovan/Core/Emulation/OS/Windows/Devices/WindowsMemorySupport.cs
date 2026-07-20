namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class WindowsMemorySupport
    {
        internal const ulong PageSize = 4096;
        internal const uint TotalPhysicalPages = 0x200000;
        internal const ulong TotalPhysicalBytes = (ulong)TotalPhysicalPages * PageSize;

        internal const ulong AvailablePhysicalBytes = 0x148000000UL;
        internal const long ResidentAvailableBytes = 0x180000000L;
        internal const ulong CommittedBytes = 0xB0000000UL;
        internal const ulong SharedCommittedBytes = 0x18000000UL;
        internal const ulong CommitLimitBytes = 0x300000000UL;
        internal const ulong PeakCommitmentBytes = 0xD0000000UL;
    }
}
