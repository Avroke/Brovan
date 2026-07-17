using System;
using System.Buffers.Binary;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySystemInformation : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // Runs for both bitnesses. Arguments come through GetArg64 (bitness-aware) and the class handlers
            // that emit pointer-sized fields branch on Architecture internally (SystemBasicInformation,
            // SystemKernelDebugger, …). This unblocks the WOW64 loader, which queries SystemBasicInformation
            // early; class-by-class 32-bit struct-size refinements are tracked separately.
            if (Instance._binary.Architecture == BinaryArchitecture.x64 || Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                SYSTEM_INFORMATION_CLASS SystemInformationClass = (SYSTEM_INFORMATION_CLASS)Instance.WinHelper.GetArg64(0);
                ulong SystemInformationPtr = Instance.WinHelper.GetArg64(1);
                ulong SystemInformationLength = Instance.WinHelper.GetArg64(2);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(3);

                if (SystemInformationPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (SystemInformationLength == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(SystemInformationPtr, SystemInformationLength))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                switch (SystemInformationClass)
                {
                    case SYSTEM_INFORMATION_CLASS.SystemProcessorFeaturesBitMapInformation:
                        {
                            if (SystemInformationLength != 0)
                                Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, (uint)SystemInformationLength);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, 0u);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemBuildVersionInformation:
                        {
                            const uint RequiredLength = WindowsVersionInfo.BuildVersionInformationLength;

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            if (SystemInformationLength < RequiredLength)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            WindowsVersionInfo.WriteBuildVersionInformation(Instance, SystemInformationPtr);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemTimeOfDayInformation:
                        {
                            const uint FullSize = 0x30;

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, FullSize);
                            }

                            if (SystemInformationLength < FullSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            long CurrentTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
                            long MaxFileTime = DateTime.SpecifyKind(DateTime.MaxValue, DateTimeKind.Utc).ToFileTimeUtc();
                            DateTime CurrentUtc = DateTime.FromFileTimeUtc(Math.Min(CurrentTime, MaxFileTime));
                            DateTime LocalNow = TimeZoneInfo.ConvertTimeFromUtc(CurrentUtc, TimeZoneInfo.Local);

                            TimeSpan Offset = TimeZoneInfo.Local.GetUtcOffset(CurrentUtc);
                            long TimeZoneBias = -Offset.Ticks;

                            long UPtime100ns = Instance.EmulatedTickCount64 * 10000;
                            long BootTime = CurrentTime - UPtime100ns;

                            uint TimeZoneId = TimeZoneInfo.Local.IsDaylightSavingTime(LocalNow) ? 2u : 1u;

                            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(FullSize);
                            Buffer.Slice(0, (int)FullSize).Clear();

                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x00, 8), BootTime);
                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x08, 8), CurrentTime);
                            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(0x10, 8), TimeZoneBias);
                            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(0x18, 4), TimeZoneId);

                            if (!Instance.WriteMemory(SystemInformationPtr, Buffer.Slice(0, (int)FullSize)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQuerySystemInformation: SystemTimeOfDayInformation (Boot=0x{BootTime:X}, Now=0x{CurrentTime:X}, TZId={TimeZoneId}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemTimeZoneInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemCurrentTimeZoneInformation:
                        {
                            uint RequiredLength = 172;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, RequiredLength);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, -120);

                            WriteUnicodeString(Instance, SystemInformationPtr + 4, "@tzres.dll,-342");

                            Instance._emulator.WriteMemory(SystemInformationPtr + 84, 0);

                            WriteUnicodeString(Instance, SystemInformationPtr + 88, "@tzres.dll,-341");

                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 2, (ushort)10);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 4, (ushort)5);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 6, (ushort)23);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 8, (ushort)59);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 10, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 12, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 68 + 14, (ushort)0);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 2, (ushort)4);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 4, (ushort)4);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 6, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 8, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 10, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 12, (ushort)0);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 152 + 14, (ushort)0);

                            Instance._emulator.WriteMemory(SystemInformationPtr + 168, -60);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemNumaProcessorMap:
                        const uint HeaderSize = 0x08;
                        const uint GroupAffinitySize = 0x10;
                        const uint MaxNodes = 0x40;

                        if (SystemInformationLength < sizeof(uint))
                        {
                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)sizeof(uint));
                            }
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        uint ClearSize = (uint)Math.Min(SystemInformationLength, HeaderSize + GroupAffinitySize);
                        Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, ClearSize);

                        Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, 0u); // HighestNodeNumber = 0

                        uint ReqSize = sizeof(uint);

                        if (SystemInformationLength >= HeaderSize + 8)
                        {
                            ulong ActiveMask = 0xFFFUL; // Single-node active processor mask
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, ActiveMask); // Node0 Mask

                            if (SystemInformationLength >= HeaderSize + 0x0A)
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, (ushort)0);

                            uint MaxEntries = (uint)((SystemInformationLength - HeaderSize) / GroupAffinitySize);
                            if (MaxEntries > MaxNodes)
                                MaxEntries = MaxNodes;

                            ReqSize = HeaderSize + (MaxEntries != 0 ? (MaxEntries * GroupAffinitySize) : 0);
                            if (ReqSize < sizeof(uint)) ReqSize = sizeof(uint);
                        }

                        if (ReturnLengthPtr != 0)
                        {
                            if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            Instance._emulator.WriteMemory(ReturnLengthPtr, ReqSize);
                        }
                        return NTSTATUS.STATUS_SUCCESS;

                    case SYSTEM_INFORMATION_CLASS.SystemCodeIntegrityInformation:
                        {
                            uint RequiredLength = 8;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            uint CodeIntegrityOptions = 0x401;

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 4, CodeIntegrityOptions);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemKernelDebuggerInformation:
                        {
                            uint RequiredLength = 2;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, (byte)0); // KernelDebuggerEnabled
                            Instance._emulator.WriteMemory(SystemInformationPtr + 1, (byte)1); // KernelDebuggerNotPresent

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemRangeStartInformation:
                        {
                            uint Required = Instance._binary.Architecture == BinaryArchitecture.x64 ? 8u : 4u;

                            if (SystemInformationLength < Required)
                            {
                                if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    Instance._emulator.WriteMemory(ReturnLengthPtr, Required);

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (SystemInformationPtr == 0)
                                return NTSTATUS.STATUS_INVALID_PARAMETER;

                            if (!Instance.IsRegionMapped(SystemInformationPtr, Required))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                            {
                                // Typical x64 kernel range start.
                                ulong RangeStart = 0xFFFF800000000000UL;
                                if (!Instance._emulator.WriteMemory(SystemInformationPtr, RangeStart, 8))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            else
                            {
                                uint RangeStart = 0x80000000u;
                                if (!Instance._emulator.WriteMemory(SystemInformationPtr, RangeStart, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }

                            if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                Instance._emulator.WriteMemory(ReturnLengthPtr, Required);

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemSecureBootInformation:
                        {
                            uint RequiredLength = 2;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0, (byte)1); // SecureBootEnabled
                            Instance._emulator.WriteMemory(SystemInformationPtr + 1, (byte)1); // SecureBootCapable

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemControlFlowTransition:
                        if ((Instance.Settings.Flags & LogFlags.Suspicious) != 0)
                            Instance.TriggerEventMessage($"[!] Warbird transition query using NtQuerySystemInformation at 0x{Instance.ReadRegister(Instance.IPRegister):X}.", LogFlags.Suspicious);
                        return NTSTATUS.STATUS_NOT_IMPLEMENTED;

                    case SYSTEM_INFORMATION_CLASS.SystemProcessInformation:
                        {
                            List<WinProcess> Processes = Instance.WinHelper.WinProcesses;
                            if (Processes == null)
                                Processes = new List<WinProcess>();

                            ulong EntrySize = 0x70;
                            ulong RequiredLength = (ulong)Processes.Count * EntrySize;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, (uint)RequiredLength);

                            ulong Current = SystemInformationPtr;

                            for (int i = 0; i < Processes.Count; i++)
                            {
                                WinProcess P = Processes[i];

                                uint NextEntryOffset = (i == Processes.Count - 1) ? 0 : (uint)EntrySize;

                                Instance._emulator.WriteMemory(Current + 0x00, NextEntryOffset);
                                Instance._emulator.WriteMemory(Current + 0x04, 1u);

                                ulong ImageNameField = Current + 0x38; // ImageName field which contains the process name.

                                if (!string.IsNullOrEmpty(P.Name) && P.Status != ProtectionStatus.Unaccessible)
                                    Instance.WinHelper.SetUnicodeString(ImageNameField, P.Name);
                                else
                                {
                                    Instance._emulator.WriteMemory(ImageNameField + 0x00, (ushort)0, 2);
                                    Instance._emulator.WriteMemory(ImageNameField + 0x02, (ushort)0, 2);
                                    Instance._emulator.WriteMemory(ImageNameField + 0x08, 0UL);
                                }

                                Instance._emulator.WriteMemory(Current + 0x48, 8);

                                Instance._emulator.WriteMemory(Current + 0x50, (ulong)P.PID); // UniqueProcessId
                                Instance._emulator.WriteMemory(Current + 0x58, (ulong)P.PPID); // InheritedFromUniqueProcessId

                                Current += EntrySize;
                            }

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemProcessorInformation:
                        {
                            const uint RequiredLength = 0x0C;

                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            ushort ProcessorArchitecture = Instance._binary.Architecture == BinaryArchitecture.x64 ? (ushort)9 : (ushort)0;
                            ushort ProcessorLevel = 6;
                            ushort ProcessorRevision = 0x0100;

                            int CpuCount = Environment.ProcessorCount;
                            if (CpuCount < 1)
                                CpuCount = 1;
                            if (CpuCount > ushort.MaxValue)
                                CpuCount = ushort.MaxValue;

                            ushort MaximumProcessors = (ushort)CpuCount;
                            uint ProcessorFeatureBits = 0;

                            Instance.WinHelper.WriteZeroMemory(SystemInformationPtr, RequiredLength);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, ProcessorArchitecture);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x02, ProcessorLevel);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, ProcessorRevision);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x06, MaximumProcessors);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, ProcessorFeatureBits);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemEmulationBasicInformation:
                    case SYSTEM_INFORMATION_CLASS.SystemBasicInformation:
                        {
                            // SYSTEM_BASIC_INFORMATION has three ULONG_PTR/KAFFINITY tail fields
                            // (MinimumUserModeAddress, MaximumUserModeAddress, ActiveProcessorsAffinityMask)
                            // that are 8 bytes on x64 / 4 bytes on x86 — so the struct is 0x40 vs 0x2C and the
                            // WOW64 loader passes a 44-byte buffer. Size the tail to the guest.
                            bool Wow64 = Instance._binary.Architecture != BinaryArchitecture.x64;
                            uint RequiredLength = Wow64 ? 0x2Cu : 0x40u;
                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            uint NumberOfPhysicalPages = WindowsMemorySupport.TotalPhysicalPages;
                            uint LowestPhysicalPageNumber = 0x00000001;
                            uint HighestPhysicalPageNumber = LowestPhysicalPageNumber + NumberOfPhysicalPages - 1;
                            uint AllocationGranularity = 0x10000;
                            uint TimerResolution = 156250;

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, 0u); // Reserved
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x04, TimerResolution);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, 4096); // PageSize
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x0C, NumberOfPhysicalPages); // NumberOfPhysicalPages
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, LowestPhysicalPageNumber); // LowestPhysicalPageNumber
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x14, HighestPhysicalPageNumber);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x18, AllocationGranularity);

                            if (Wow64)
                            {
                                // The two user-address bounds must describe the 32-bit *process* address space,
                                // NOT the emulator's internal allocation window (Instance.BaseAddress/MaxAddress).
                                // MaximumUserModeAddress in particular is load-bearing: ntdll's CFG-bitmap
                                // reservation (LdrpProtectMrdata → RtlpAllocateVirtualMemoryEx) reads it back via
                                // SystemEmulationBasicInformation, does `MaximumUserModeAddress + 1`, then derives
                                // the bitmap size from that span. (uint)Instance.MaxAddress was 0xFFFFFFFF, whose
                                // +1 overflows to 0 → a 0-byte bitmap reservation → NtAllocateVirtualMemoryEx
                                // returns STATUS_INVALID_PARAMETER → ntdll fails process init with
                                // STATUS_APP_INIT_FAILURE. Report the real Win32 bounds instead: floor 0x10000
                                // (64 KB), ceiling 0x7FFEFFFF (2 GB − 64 KB), or 0xFFFEFFFF (4 GB − 64 KB) when
                                // the image is large-address-aware — the extra 2 GB a WOW64 LAA process gets.
                                bool LargeAddressAware = Instance._binary.PE != null &&
                                    (Instance._binary.PE.Characteristics & System.Reflection.PortableExecutable.Characteristics.LargeAddressAware) != 0;
                                uint MinimumUserModeAddress = 0x00010000;
                                uint MaximumUserModeAddress = LargeAddressAware ? 0xFFFEFFFFu : 0x7FFEFFFFu;
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x1C, MinimumUserModeAddress);      // MinimumUserModeAddress
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x20, MaximumUserModeAddress);      // MaximumUserModeAddress
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x24, 0x1u);                        // ActiveProcessorsAffinityMask
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x28, (byte)Environment.ProcessorCount);
                            }
                            else
                            {
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x20, Instance.BaseAddress);
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x28, Instance.MaxAddress);
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x30, 0x1);
                                Instance._emulator.WriteMemory(SystemInformationPtr + 0x38, (byte)Environment.ProcessorCount);
                            }

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, (uint)RequiredLength);
                            }
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case SYSTEM_INFORMATION_CLASS.SystemMemoryUsageInformation:
                        {
                            // SYSTEM_MEMORY_USAGE_INFORMATION (0x38 bytes). This is the ONLY class
                            // modern kernelbase!GlobalMemoryStatusEx queries; returning
                            // STATUS_NOT_SUPPORTED left MEMORYSTATUSEX unfilled (ullTotalPhys == 0),
                            // reading as a sub-2 GB VM. All figures come from the RAM SSOT.
                            const uint RequiredLength = 0x38;
                            if (SystemInformationLength < RequiredLength)
                            {
                                if (ReturnLengthPtr != 0)
                                {
                                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                    Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                                }

                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x00, WindowsMemorySupport.TotalPhysicalBytes, 8);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x08, WindowsMemorySupport.AvailablePhysicalBytes, 8);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x10, unchecked((ulong)WindowsMemorySupport.ResidentAvailableBytes), 8);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x18, WindowsMemorySupport.CommittedBytes, 8);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x20, WindowsMemorySupport.SharedCommittedBytes, 8);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x28, WindowsMemorySupport.CommitLimitBytes, 8);
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x30, WindowsMemorySupport.PeakCommitmentBytes, 8);

                            if (ReturnLengthPtr != 0)
                            {
                                if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                Instance._emulator.WriteMemory(ReturnLengthPtr, RequiredLength);
                            }
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case SYSTEM_INFORMATION_CLASS.SystemFirmwareTableInformation:
                        {
                            // GetSystemFirmwareTable / EnumSystemFirmwareTables route here via a
                            // SYSTEM_FIRMWARE_TABLE_INFORMATION struct: ProviderSignature (+0x00),
                            // Action (+0x04), TableID (+0x08), TableBufferLength (+0x0C), TableBuffer
                            // (+0x10). We answer the 'ACPI' provider with a bare-metal-realistic table
                            // set: a real machine always exposes ACPI tables, so code that reads an
                            // absent/unenumerable ACPI firmware table as an emulator tell sees a normal
                            // host. OEM strings are common AMI/desktop values with NO hypervisor
                            // signature, so a firmware VM-string scan finds nothing. Other providers
                            // (RSMB / FIRM) fall through to the default path unchanged (still fail).
                            const uint FirmwareHeaderLen = 0x10;
                            if (SystemInformationLength < FirmwareHeaderLen)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            uint ProviderSignature = Instance.ReadMemoryUInt(SystemInformationPtr + 0x00);
                            uint FirmwareAction = Instance.ReadMemoryUInt(SystemInformationPtr + 0x04);
                            uint FirmwareTableId = Instance.ReadMemoryUInt(SystemInformationPtr + 0x08);
                            uint TableBufferLength = Instance.ReadMemoryUInt(SystemInformationPtr + 0x0C);

                            const uint AcpiProvider = 0x41435049; // 'ACPI'
                            if (ProviderSignature != AcpiProvider)
                                break; // unsupported provider -> default (unimplemented), unchanged

                            byte[] FirmwareData;
                            if (FirmwareAction == 0) // SystemFirmwareTable_Enumerate
                            {
                                FirmwareData = AcpiEnumerateTables();
                            }
                            else if (FirmwareAction == 1) // SystemFirmwareTable_Get
                            {
                                FirmwareData = AcpiGetTable(FirmwareTableId);
                                // Only the tables we actually enumerate exist. A Get for any other
                                // signature (e.g. a probe that reads a hypervisor-specific table such
                                // as QEMU's 'PCAF' and inspects a fixed byte) must fail exactly as it
                                // would on bare metal where that table is absent. Report size 0 so the
                                // GetSystemFirmwareTable wrapper returns 0 ("table not present") instead
                                // of leaving the caller's input TableBufferLength in place — which a probe
                                // would read as "table exists" and then inspect at a fixed offset.
                                if (FirmwareData == null)
                                {
                                    Instance._emulator.WriteMemory(SystemInformationPtr + 0x0C, 0u);
                                    if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                        Instance._emulator.WriteMemory(ReturnLengthPtr, FirmwareHeaderLen);
                                    return NTSTATUS.STATUS_NOT_FOUND;
                                }
                            }
                            else
                            {
                                break; // unsupported action (e.g. register handler) -> default
                            }

                            // GetSystemFirmwareTable reads TableBufferLength back as the actual size.
                            Instance._emulator.WriteMemory(SystemInformationPtr + 0x0C, (uint)FirmwareData.Length);

                            uint CopyLen = Math.Min(TableBufferLength, (uint)FirmwareData.Length);
                            if (CopyLen > 0)
                            {
                                if (!Instance.IsRegionMapped(SystemInformationPtr + FirmwareHeaderLen, CopyLen))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                byte[] Slice = CopyLen == FirmwareData.Length ? FirmwareData : FirmwareData[..(int)CopyLen];
                                Instance.WriteMemory(SystemInformationPtr + FirmwareHeaderLen, Slice);
                            }

                            if (ReturnLengthPtr != 0 && Instance.IsRegionMapped(ReturnLengthPtr, 4))
                                Instance._emulator.WriteMemory(ReturnLengthPtr, FirmwareHeaderLen + (uint)FirmwareData.Length);

                            return TableBufferLength >= (uint)FirmwareData.Length
                                ? NTSTATUS.STATUS_SUCCESS
                                : NTSTATUS.STATUS_BUFFER_TOO_SMALL;
                        }

                    default:
                        if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                            Instance.TriggerEventMessage($"[!] Unsupported NtQuerySystemInformation class: 0x{SystemInformationClass:X}", LogFlags.Issues);
                        break;
                }
            }
            return Instance.WinUnimplemented;
        }

        private const uint AcpiSigSSDT = 0x54445353; // 'SSDT'

        // Bare-metal-realistic ACPI signature set. Deliberately EXCLUDES 'WAET' (the "Windows ACPI
        // Emulated devices Table" — its presence is itself a virtualization tell) and INCLUDES 'WSMT'
        // (Windows SMM Security Mitigations Table — present on real modern machines; its absence is a
        // tell). Stored as the little-endian DWORDs EnumSystemFirmwareTables returns / GetSystemFirmware
        // Table takes back as TableID.
        private static readonly uint[] AcpiTableSignatures =
        {
            0x50434146, // 'FACP' (FADT)
            0x43495041, // 'APIC'
            0x54455048, // 'HPET'
            0x4746434D, // 'MCFG'
            AcpiSigSSDT, // 'SSDT'
            0x54524742, // 'BGRT'
            0x544D5357, // 'WSMT'
        };

        // Standard ACPI PnP hardware IDs a real firmware exposes (PS/2, power/sleep buttons, container,
        // memory). Embedded (as ASCII, the form a firmware string scan matches) in the SSDT body so a
        // scan that treats the ABSENCE of real PnP devices as a virtualization tell is satisfied.
        private static readonly byte[] AcpiSsdtDeviceIds =
            System.Text.Encoding.ASCII.GetBytes("PNP0000\0PNP0C0C\0PNP0C0E\0PNP0C14\0PNP0D80\0");

        private static bool IsKnownAcpiTable(uint Signature)
        {
            foreach (uint Sig in AcpiTableSignatures)
                if (Sig == Signature)
                    return true;
            return false;
        }

        private static byte[] AcpiEnumerateTables()
        {
            byte[] Out = new byte[AcpiTableSignatures.Length * 4];
            for (int i = 0; i < AcpiTableSignatures.Length; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(Out.AsSpan(i * 4, 4), AcpiTableSignatures[i]);
            return Out;
        }

        private static byte[] AcpiGetTable(uint TableId)
        {
            // Only the tables we enumerate exist; anything else is absent (bare-metal behavior).
            if (!IsKnownAcpiTable(TableId))
                return null;

            // Minimal but well-formed ACPI table: the 36-byte common header + a body, with a corrected
            // 8-bit checksum (whole table sums to 0 mod 256). OEM fields are the ubiquitous AMI/desktop
            // strings — bare metal, no VM signature. The SSDT carries the standard PnP device IDs.
            const int HeaderLen = 36;
            byte[] Body = TableId == AcpiSigSSDT ? AcpiSsdtDeviceIds : new byte[16];
            byte[] Table = new byte[HeaderLen + Body.Length];
            Span<byte> S = Table;

            BinaryPrimitives.WriteUInt32LittleEndian(S.Slice(0, 4), TableId); // Signature
            BinaryPrimitives.WriteUInt32LittleEndian(S.Slice(4, 4), (uint)Table.Length);                   // Length
            S[8] = 3;                                                                                       // Revision
            S[9] = 0;                                                                                       // Checksum (computed below)
            WriteAcpiAscii(S.Slice(10, 6), "ALASKA");                                                      // OEMID
            WriteAcpiAscii(S.Slice(16, 8), "A M I ");                                                       // OEM Table ID
            BinaryPrimitives.WriteUInt32LittleEndian(S.Slice(24, 4), 0x01072009);                          // OEM Revision
            WriteAcpiAscii(S.Slice(28, 4), "AMI ");                                                         // Creator ID
            BinaryPrimitives.WriteUInt32LittleEndian(S.Slice(32, 4), 0x00010013);                          // Creator Revision
            Body.CopyTo(S.Slice(HeaderLen));                                                                // table-specific body

            byte Sum = 0;
            foreach (byte B in Table)
                Sum += B;
            S[9] = (byte)(0x100 - Sum);
            return Table;
        }

        private static void WriteAcpiAscii(Span<byte> Dest, string Value)
        {
            for (int i = 0; i < Dest.Length; i++)
                Dest[i] = (byte)(i < Value.Length ? Value[i] : 0x20);
        }

        private static void WriteUnicodeString(BinaryEmulator Instance, ulong Address, string Value)
        {
            int ByteCount = Encoding.Unicode.GetByteCount(Value) + 2;
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan((uint)ByteCount);
            Encoding.Unicode.GetBytes(Value.AsSpan(), Buffer);
            Buffer[ByteCount - 2] = 0;
            Buffer[ByteCount - 1] = 0;
            Instance._emulator.WriteMemory(Address, Buffer.Slice(0, ByteCount));
        }

    }
}
