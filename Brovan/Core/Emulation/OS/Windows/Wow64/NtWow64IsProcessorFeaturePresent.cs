namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// WOW64 direct-syscall form of <c>IsProcessorFeaturePresent(ULONG ProcessorFeature)</c>. Kernel32's
    /// <c>IsProcessorFeaturePresent</c> reads <c>KUSER_SHARED_DATA.ProcessorFeatures[i]</c> directly; WOW64
    /// samples that go through the syscall stub hit this SSN instead. To keep the two paths byte-identical
    /// (a sample can cross-check them), this reads the SAME table — the 64-entry BOOLEAN
    /// <c>ProcessorFeatures[]</c> array at <c>KUSER_SHARED_DATA+0x274</c> that <c>WinInternalHelper</c>
    /// populates — rather than duplicating the feature-bit list, so a future edit to that table can't leave
    /// this handler drifting behind it.
    /// </summary>
    internal class NtWow64IsProcessorFeaturePresent : IWinSyscall
    {
        private const uint ProcessorFeatureMax = 64;        // PROCESSOR_FEATURE_MAX — array length.
        private const ulong ProcessorFeaturesOffset = 0x274; // KUSER_SHARED_DATA.ProcessorFeatures.

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            uint Feature = (uint)Instance.WinHelper.GetArg64(0);

            bool Present = Feature < ProcessorFeatureMax
                && (Instance.ReadMemoryUInt(Instance.KUSER_SHARED_DATA + ProcessorFeaturesOffset + Feature) & 0xFF) != 0;

            Instance.SetRawSyscallReturn(Present ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
