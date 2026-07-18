namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// WOW64 direct-syscall form of <c>IsProcessorFeaturePresent(ULONG ProcessorFeature)</c>. Kernel32's
    /// <c>IsProcessorFeaturePresent</c> normally reads <c>KUSER_SHARED_DATA.ProcessorFeatures[i]</c>
    /// directly, but WOW64 samples that go through the syscall stub hit this SSN. Feature bits mirror the
    /// KUSER_SHARED_DATA table Brovan already publishes
    /// (see <c>WinInternalHelper</c> — SSE / SSE2 / SSE3 / NX / FASTFAIL / RDRAND / RDTSCP), so a caller
    /// that cross-checks the two paths gets the same answer.
    /// </summary>
    internal class NtWow64IsProcessorFeaturePresent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Feature = (uint)Instance.WinHelper.GetArg64(0);
            // Bits set: 6=SSE, 10=SSE2, 13=SSE3, 12=NX, 23=FASTFAIL, 28=RDRAND, 32=RDTSCP. Any other
            // feature index reports absent, matching what a stripped sandbox CPU would report.
            bool Present = Feature == 6 || Feature == 10 || Feature == 13 || Feature == 12
                        || Feature == 23 || Feature == 28 || Feature == 32;
            Instance.SetRawSyscallReturn(Present ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
