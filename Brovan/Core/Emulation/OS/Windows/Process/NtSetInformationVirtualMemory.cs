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
        private const uint MaxVmInfoClass = 8;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64 && Instance._binary.Architecture != BinaryArchitecture.x86)
                return Instance.WinUnimplemented;

            ulong MemoryRangeEntrySize = (ulong)(Instance.GuestPointerSize * 2);

            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            uint VmInformationClass = (uint)Instance.WinHelper.GetArg64(1);
            ulong NumberOfEntries = Instance.WinHelper.GetArg64(2);
            ulong VirtualAddresses = Instance.WinHelper.GetArg64(3);
            ulong VmInformation = Instance.WinHelper.GetArg64(4);
            uint VmInformationLength = (uint)Instance.WinHelper.GetArg64(5);

            if (VmInformationClass >= MaxVmInfoClass)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            bool CurrentProcess = Instance.WinHelper.IsCurrentProcessPseudoHandle(ProcessHandle);
            if (!CurrentProcess && Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle) == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

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
                    ulong RangeVirtualAddress = Instance.ReadPointer(Entry + 0x0);
                    ulong RangeNumberOfBytes = Instance.ReadPointer(Entry + (ulong)Instance.GuestPointerSize);
                    _ = RangeVirtualAddress;
                    _ = RangeNumberOfBytes;
                }
            }

            if (VmInformationLength != 0 && (VmInformation == 0 || !Instance.IsRegionMapped(VmInformation, VmInformationLength)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
