using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtSetInformationVirtualMemory (SSN 0x19E on 19041/19044). Applies an advisory
    /// operation to one or more virtual-address ranges of a process: prefetch hints,
    /// page-priority, CFG call-target registration (SetProcessValidCallTargets),
    /// working-set trimming, hot-patch / contiguity / VM-prepopulate. The MSVC loader/CRT
    /// call it during startup (al-khaser exercises it dozens of times per run), so leaving
    /// it as STATUS_NOT_SUPPORTED both spams the trace and is a fidelity tell.
    ///
    /// None of the classes changes the observable contents of emulated memory (they are
    /// scheduler / working-set / CFG hints the sandbox does not enforce), so once the
    /// arguments validate the faithful result is success.
    /// </summary>
    internal class NtSetInformationVirtualMemory : IWinSyscall
    {
        // VIRTUAL_MEMORY_INFORMATION_CLASS: VmPrefetchInformation(0) .. VmRemoveFromWorkingSetInformation(7).
        private const uint MaxVmInfoClass = 8;

        // MEMORY_RANGE_ENTRY { PVOID VirtualAddress; SIZE_T NumberOfBytes; } is 16 bytes on x64.
        private const ulong MemoryRangeEntrySize = 0x10;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            uint VmInformationClass = (uint)Instance.WinHelper.GetArg64(1);
            ulong NumberOfEntries = Instance.WinHelper.GetArg64(2);
            ulong VirtualAddresses = Instance.WinHelper.GetArg64(3);
            ulong VmInformation = Instance.WinHelper.GetArg64(4);
            uint VmInformationLength = (uint)Instance.WinHelper.GetArg64(5);

            if (VmInformationClass >= MaxVmInfoClass)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Non-current process handles are rare here; the operation is advisory, so accept the
            // current-process pseudo-handle and a resolvable process handle, and fail an outright
            // bogus one the way the real service does.
            bool CurrentProcess = ProcessHandle == ulong.MaxValue;
            if (!CurrentProcess && Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle) == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            // The MEMORY_RANGE_ENTRY array the operation applies to. A set pointer must be readable
            // (a bad pointer #GP-faults inside the real service); read each entry so the argument is
            // fully consumed.
            if (NumberOfEntries != 0 && VirtualAddresses != 0)
            {
                if (NumberOfEntries > ulong.MaxValue / MemoryRangeEntrySize)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong ArraySize = NumberOfEntries * MemoryRangeEntrySize;
                if (!Instance.IsRegionMapped(VirtualAddresses, ArraySize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                for (ulong i = 0; i < NumberOfEntries; i++)
                {
                    ulong Entry = VirtualAddresses + (i * MemoryRangeEntrySize);
                    ulong RangeVirtualAddress = Instance.ReadMemoryULong(Entry + 0x0);
                    ulong RangeNumberOfBytes = Instance.ReadMemoryULong(Entry + 0x8);
                    _ = RangeVirtualAddress;
                    _ = RangeNumberOfBytes;
                }
            }

            // The per-class payload (CFG call-target list, page-priority word, prefetch flags, ...).
            if (VmInformationLength != 0 && (VmInformation == 0 || !Instance.IsRegionMapped(VmInformation, VmInformationLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
