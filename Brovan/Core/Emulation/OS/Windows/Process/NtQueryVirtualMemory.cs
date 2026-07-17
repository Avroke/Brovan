using System;
using System.Buffers.Binary;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryVirtualMemory : IWinSyscall
    {
        private const ulong MemCommit = 0x00001000UL;
        private const ulong MemReserve = 0x00002000UL;
        private const ulong MemFree = 0x00010000UL;

        private const ulong MemPrivate = 0x00020000UL;
        private const ulong MemImage = 0x01000000UL;

        private const ulong PageGuard = 0x00000100UL;

        // x64 user-mode address-space ceiling (MmHighestUserAddress). ntdll returns
        // STATUS_INVALID_PARAMETER for a MemoryBasicInformation query above this, and the
        // canonical VirtualQuery region-walk (`while (VirtualQuery(addr)) addr += RegionSize;`)
        // relies on that failure to terminate.
        private const ulong MmHighestUserAddress = 0x00007FFFFFFEFFFFUL;

        // Start of the x64 kernel-mode canonical range. Addresses at/above this are left on the
        // existing lookup path so kernel-mode driver queries are not affected by the user-ceiling
        // termination gate; only the user-space + non-canonical hole above MmHighestUserAddress
        // is failed (which is what makes a user-mode walk stop).
        private const ulong KernelCanonicalBase = 0xFFFF800000000000UL;

        private static ulong AlignDownPage(ulong Address)
        {
            return Address & ~0xFFFUL;
        }

        private static bool IsCurrentProcess(BinaryEmulator Instance, ulong ProcessHandle)
        {
            if (Instance.WinHelper.IsCurrentProcessPseudoHandle(ProcessHandle))
                return true;

            WinProcess Proc = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
            if (Proc != null && Proc.PID == Instance.WinHelper.PID)
                return true;

            return false;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // MemoryBasicInformation is serialized bitness-aware below; the other, less common classes still
            // emit x64 layouts, so they are gated to x64 for now (an x86 query of them returns unimplemented
            // rather than corrupting the caller's buffer).
            if (Instance._binary.Architecture == BinaryArchitecture.x64 || Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                bool Wow64 = Instance._binary.Architecture != BinaryArchitecture.x64;
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong Address = Instance.WinHelper.GetArg64(1);
                MEMORY_INFORMATION_CLASS MemoryInformationClass = (MEMORY_INFORMATION_CLASS)Instance.WinHelper.GetArg64(2);
                ulong MemoryInformation = Instance.WinHelper.GetArg64(3);
                ulong MemoryInformationLength = Instance.WinHelper.GetArg64(4);
                ulong ReturnLength = Instance.WinHelper.GetArg64(5);

                if (!IsCurrentProcess(Instance, ProcessHandle))
                    return Instance.WinUnimplemented;

                if (MemoryInformation == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ReturnLength != 0 && !Instance.IsRegionMapped(ReturnLength, (ulong)Instance.GuestPointerSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (Wow64 &&
                    MemoryInformationClass != MEMORY_INFORMATION_CLASS.MemoryBasicInformation &&
                    MemoryInformationClass != MEMORY_INFORMATION_CLASS.MemoryPrivilegedBasicInformation &&
                    MemoryInformationClass != MEMORY_INFORMATION_CLASS.MemoryImageInformation &&
                    MemoryInformationClass != MEMORY_INFORMATION_CLASS.MemoryWorkingSetExInformation)
                {
                    Instance.TriggerEventMessage($"[!] NtQueryVirtualMemory (x86): class {MemoryInformationClass} not implemented", LogFlags.Issues);
                    return Instance.WinUnimplemented;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryBasicInformation || MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryPrivilegedBasicInformation)
                {
                    // Above the user-mode ceiling (but below the kernel canonical range) ntdll fails
                    // the query; without this a walk that steps past the highest mapped region would
                    // get an endless run of 0x1000-byte MEM_FREE regions (see the free-region branch
                    // below) and never terminate. Kernel addresses stay on the normal path so driver
                    // queries are unaffected.
                    if (Address > MmHighestUserAddress && Address < KernelCanonicalBase)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    // MEMORY_BASIC_INFORMATION size is bitness-dependent (three pointer-sized fields): 0x1C on
                    // x86, 0x30 on x64. The struct is declared with fixed ulong fields so GetStructSize always
                    // reports 0x30 — hardcode the guest size so a 32-bit caller's 0x1C buffer isn't rejected.
                    ulong RequiredLength = Wow64 ? 0x1CUL : 0x30UL;

                    if (ReturnLength != 0)
                    {
                        if (!Instance.WritePointer(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong QueryAddress = AlignDownPage(Address);

                    bool HasRegion = Instance.TryFindMemoryRegion(QueryAddress, out MemoryRegion Region);

                    MemoryRegion Freed = default;
                    bool HasFreed = false;

                    if (!HasRegion)
                    {
                        Freed = Instance._freedmemory.FirstOrDefault(R => QueryAddress >= R.BaseAddress && QueryAddress < (R.BaseAddress + R.Size));
                        HasFreed = Freed.BaseAddress != 0;
                    }

                    MEMORY_BASIC_INFORMATION Info = new MEMORY_BASIC_INFORMATION();

                    if (HasRegion)
                    {
                        bool IsImage = Region.Flags.HasFlag(AllocationType.Image);

                        bool IsCommitted =
                            Region.IsCommitted ||
                            Region.Flags.HasFlag(AllocationType.Commited) ||
                            IsImage ||
                            Region.Protections != MemoryProtection.None;

                        bool IsReserved =
                            Region.IsReserved ||
                            Region.Flags.HasFlag(AllocationType.Reserved) ||
                            (!IsCommitted && Region.BaseAddress != 0);

                        Info.BaseAddress = Region.BaseAddress;

                        ulong AllocationBase = Region.AllocationBase != 0 ? Region.AllocationBase : Region.BaseAddress;
                        Info.AllocationBase = AllocationBase;

                        ulong AllocationProtect = Region.AllocationProtect != 0 ? Region.AllocationProtect : Instance.WinHelper.ConvertInternalToWinProtect(Region.InitialProtections);

                        Info.AllocationProtect = (uint)AllocationProtect;

                        Info.PartitionId = 0;
                        Info.RegionSize = Region.Size;

                        if (IsCommitted)
                            Info.State = (uint)MemCommit;
                        else if (IsReserved)
                            Info.State = (uint)MemReserve;
                        else
                            Info.State = 0;

                        if (IsCommitted)
                        {
                            ulong Protect = Instance.WinHelper.ConvertInternalToWinProtect(Region.Protections);
                            if (Region.SpecialProtections.HasFlag(SpecialProtections.Guard))
                                Protect |= PageGuard;

                            Info.Protect = (uint)Protect;
                        }
                        else
                        {
                            Info.Protect = 0;
                        }

                        Info.Type = IsImage ? (uint)MemImage : (uint)MemPrivate;
                    }
                    else
                    {
                        ulong FreeBase;
                        ulong FreeSize;

                        if (HasFreed)
                        {
                            FreeBase = Freed.BaseAddress;
                            FreeSize = Freed.Size;
                        }
                        else
                        {
                            ulong Next = ulong.MaxValue;

                            if (Instance.TryFindNextMemoryRegionBase(QueryAddress, out ulong NextMapped) && NextMapped < Next)
                                Next = NextMapped;

                            foreach (var R in Instance._freedmemory)
                            {
                                if (R.BaseAddress > QueryAddress && R.BaseAddress < Next)
                                    Next = R.BaseAddress;
                            }

                            FreeBase = QueryAddress;
                            // No further mapped/freed region above: real ntdll reports the whole free
                            // span up to the user-mode ceiling as ONE region, so the walk advances past
                            // the ceiling in a single step and the next query fails — instead of marching
                            // through the address space in 0x1000-byte chunks forever. Only extend to the
                            // ceiling for user-space bases; a kernel-address query (driver path) keeps the
                            // single-page fallback so its size can't underflow.
                            if (Next != ulong.MaxValue)
                                FreeSize = Next - FreeBase;
                            else if (FreeBase <= MmHighestUserAddress)
                                FreeSize = MmHighestUserAddress - FreeBase + 1;
                            else
                                FreeSize = 0x1000UL;

                            if (FreeSize == 0)
                                FreeSize = 0x1000UL;
                        }

                        Info.BaseAddress = FreeBase;
                        Info.AllocationBase = 0;
                        Info.AllocationProtect = 0;
                        Info.PartitionId = 0;
                        Info.RegionSize = FreeSize;
                        Info.State = (uint)MemFree;
                        Info.Protect = 0;
                        Info.Type = 0;
                    }

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    if (Instance._binary.Architecture != BinaryArchitecture.x64)
                    {
                        // x86 MEMORY_BASIC_INFORMATION — 28 bytes, all pointer fields 4-wide.
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x00, 4), (uint)Info.BaseAddress);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x04, 4), (uint)Info.AllocationBase);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x08, 4), Info.AllocationProtect);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x0C, 4), (uint)Info.RegionSize);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x10, 4), Info.State);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x14, 4), Info.Protect);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x18, 4), Info.Type);
                    }
                    else
                    {
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Info.BaseAddress);
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Info.AllocationBase);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x10, 4), Info.AllocationProtect);
                        BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(0x14, 2), Info.PartitionId);
                        BinaryPrimitives.WriteUInt16LittleEndian(Data.Slice(0x16, 2), Info.Reserved);
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x18, 8), Info.RegionSize);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x20, 4), Info.State);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x24, 4), Info.Protect);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x28, 4), Info.Type);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x2C, 4), Info.Reserved2);
                    }

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }


                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryMappedFilenameInformation)
                {
                    if (!Instance.IsRegionMapped(MemoryInformation, MemoryInformationLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    WinModule Module = Instance.WinHelper.FindMappedImageViewByAddress(Address);
                    if (Module == null)
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    string Path = !string.IsNullOrEmpty(Module.Path) ? Module.Path : Module.Name;
                    if (string.IsNullOrEmpty(Path))
                        Path = Module.CanonicalImagePath;

                    if (string.IsNullOrEmpty(Path))
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    // GetMappedFileName / NtQueryVirtualMemory(MemoryMappedFilenameInformation) returns
                    // the NT device path (\Device\HarddiskVolumeN\...), NOT a \??\C: DOS-device path.
                    // al-khaser's "hidden modules" walk gets this name per mapped image and converts it
                    // back to a drive letter via the device map to match the loader list; the \??\C:
                    // form doesn't convert, so every System32 module was reported as an injected library.
                    Path = Instance.WinHelper.DosPathToNtDevicePath(Path);

                    int StringByteCount = Encoding.Unicode.GetByteCount(Path) + 2;
                    Span<byte> StringData = Instance.WinHelper.Shared.GetSpan((uint)StringByteCount);
                    Encoding.Unicode.GetBytes(Path.AsSpan(), StringData);
                    StringData[StringByteCount - 2] = 0;
                    StringData[StringByteCount - 1] = 0;
                    ulong RequiredLength = 0x10UL + (ulong)StringByteCount;

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

                    ulong Buffer = MemoryInformation + 0x10;
                    ushort Length = (ushort)(StringByteCount - 2);
                    ushort MaximumLength = (ushort)StringByteCount;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x0, Length, 2))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x2, MaximumLength, 2))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x4, 0u, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(MemoryInformation + 0x8, Buffer, 8))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.WriteMemory(Buffer, StringData.Slice(0, StringByteCount)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryWorkingSetExInformation)
                {
                    // MEMORY_WORKING_SET_EX_INFORMATION = { PVOID VirtualAddress; ULONG_PTR Flags; } — 8 bytes
                    // on x86, 16 on x64.
                    ulong ElementSize = Wow64 ? 8UL : 16UL;

                    if (ReturnLength != 0)
                    {
                        if (!Instance.WritePointer(ReturnLength, MemoryInformationLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < ElementSize)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if ((MemoryInformationLength % ElementSize) != 0)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, MemoryInformationLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong BuildFlags(bool Valid, ulong Win32Protect, bool Shared)
                    {
                        ulong Flags = 0;

                        if (!Valid)
                            return 0;

                        ulong ShareCount = Shared ? 1UL : 0UL;

                        Flags |= 1UL; // Valid
                        Flags |= (ShareCount & 0x7UL) << 1;
                        Flags |= (Win32Protect & 0x7FFUL) << 4;
                        Flags |= (Shared ? 1UL : 0UL) << 15;
                        Flags |= 0UL << 16; // Node
                        Flags |= 0UL << 22; // Locked
                        Flags |= 0UL << 23; // LargePage
                        Flags |= 0UL << 24; // Priority
                        Flags |= 0UL << 27; // Reserved
                        Flags |= (Shared ? 1UL : 0UL) << 30; // SharedOriginal
                        Flags |= 0UL << 31; // Bad
                        return Flags;
                    }

                    ulong Count = MemoryInformationLength / ElementSize;
                    for (ulong i = 0; i < Count; i++)
                    {
                        ulong Entry = MemoryInformation + (i * ElementSize);
                        ulong Va = Instance.ReadPointer(Entry + 0x0);

                        ulong PageVa = AlignDownPage(Va);

                        bool HasRegion = Instance.TryFindMemoryRegion(PageVa, out MemoryRegion Region);
                        bool IsImage = HasRegion && Region.Flags.HasFlag(AllocationType.Image);

                        bool IsCommitted =
                            HasRegion &&
                            (Region.IsCommitted ||
                             Region.Flags.HasFlag(AllocationType.Commited) ||
                             IsImage ||
                             Region.Protections != MemoryProtection.None);

                        ulong Protect = 0;
                        if (IsCommitted)
                        {
                            Protect = Instance.WinHelper.ConvertInternalToWinProtect(Region.Protections);
                            if (Region.SpecialProtections.HasFlag(SpecialProtections.Guard))
                                Protect |= PageGuard;
                        }

                        ulong Flags = BuildFlags(IsCommitted, Protect, IsImage);

                        if (!Instance.WritePointer(Entry + (ulong)Instance.GuestPointerSize, Flags))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryImageExtensionInformation)
                {
                    ulong RequiredLength = (ulong)StructSerializer.GetStructSize<MEMORY_IMAGE_EXTENSION_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong QueryAddress = AlignDownPage(Address);

                    if (!Instance.TryFindMemoryRegion(QueryAddress, out MemoryRegion Region) || !Region.Flags.HasFlag(AllocationType.Image))
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    uint RequestedType = Instance._emulator.ReadMemoryUInt(MemoryInformation + 0x0);
                    if (RequestedType > 1)
                        RequestedType = 0;

                    MEMORY_IMAGE_EXTENSION_INFORMATION Info = new MEMORY_IMAGE_EXTENSION_INFORMATION
                    {
                        ExtensionType = (MEMORY_IMAGE_EXTENSION_TYPE)RequestedType,
                        Flags = 0,
                        ExtensionImageBaseRva = 0,
                        ExtensionSize = 0
                    };

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x00, 4), (uint)Info.ExtensionType);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x04, 4), Info.Flags);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Info.ExtensionImageBaseRva);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Info.ExtensionSize);

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryRegionInformation)
                {
                    ulong RequiredLength = (ulong)StructSerializer.GetStructSize<MEMORY_REGION_INFORMATION>(Instance);

                    if (ReturnLength != 0)
                    {
                        if (!Instance._emulator.WriteMemory(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong QueryAddress = AlignDownPage(Address);

                    if (!Instance.TryFindMemoryRegion(QueryAddress, out MemoryRegion Region))
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    ulong GetAllocBase(MemoryRegion R)
                    {
                        if (R.AllocationBase != 0)
                            return R.AllocationBase;
                        return R.BaseAddress;
                    }

                    ulong AllocationBase = GetAllocBase(Region);

                    ulong MaxEnd = 0;
                    ulong CommitSize = 0;
                    bool AnyImage = false;

                    foreach (var R in Instance._memory)
                    {
                        if (GetAllocBase(R) != AllocationBase)
                            continue;

                        ulong End = R.BaseAddress + R.Size;
                        if (End > MaxEnd)
                            MaxEnd = End;

                        bool IsImage = R.Flags.HasFlag(AllocationType.Image);
                        AnyImage |= IsImage;

                        bool IsCommitted = R.IsCommitted || R.Flags.HasFlag(AllocationType.Commited) || IsImage || R.Protections != MemoryProtection.None;

                        if (IsCommitted)
                            CommitSize += R.Size;
                    }

                    if (MaxEnd <= AllocationBase)
                        MaxEnd = AllocationBase + Region.Size;

                    ulong AllocationProtect = Region.AllocationProtect != 0 ? Region.AllocationProtect : Instance.WinHelper.ConvertInternalToWinProtect(Region.InitialProtections);

                    uint RegionType = 0;
                    if (AnyImage)
                    {
                        RegionType |= (1u << 2); // MappedImage
                    }
                    else
                    {
                        RegionType |= 1u; // Private
                    }

                    MEMORY_REGION_INFORMATION Info = new MEMORY_REGION_INFORMATION
                    {
                        AllocationBase = AllocationBase,
                        AllocationProtect = (uint)AllocationProtect,
                        RegionType = RegionType,
                        RegionSize = MaxEnd - AllocationBase,
                        CommitSize = CommitSize,
                        PartitionId = 0,
                        NodePreference = ulong.MaxValue
                    };

                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Info.AllocationBase);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x08, 4), Info.AllocationProtect);
                    BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x0C, 4), Info.RegionType);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Info.RegionSize);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x18, 8), Info.CommitSize);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x20, 8), Info.PartitionId);
                    BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x28, 8), Info.NodePreference);

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (MemoryInformationClass == MEMORY_INFORMATION_CLASS.MemoryImageInformation)
                {
                    // MEMORY_IMAGE_INFORMATION: 0x0C on x86, 0x18 on x64 (fixed ulong fields ⇒ GetStructSize
                    // always reports 0x18, so size to the guest explicitly).
                    ulong RequiredLength = Wow64 ? 0x0CUL : 0x18UL;

                    if (ReturnLength != 0)
                    {
                        if (!Instance.WritePointer(ReturnLength, RequiredLength))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if (MemoryInformationLength < RequiredLength)
                        return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                    if (!Instance.IsRegionMapped(MemoryInformation, RequiredLength))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    WinModule Module = Instance.WinHelper.FindMappedImageViewByAddress(Address);

                    if (Module == null)
                        return NTSTATUS.STATUS_INVALID_ADDRESS;

                    MEMORY_IMAGE_INFORMATION Info = new MEMORY_IMAGE_INFORMATION
                    {
                        ImageBase = Module.MappedBase,
                        SizeOfImage = Module.SizeOfImage,
                        Flags = 0
                    };

                    // MEMORY_IMAGE_INFORMATION: ImageBase (PVOID) + SizeOfImage (SIZE_T) are pointer-sized;
                    // Flags is a ULONG bitfield union. x86 = 0x0C, x64 = 0x18.
                    Span<byte> Data = Instance.WinHelper.Shared.GetSpan(RequiredLength);
                    if (Wow64)
                    {
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x00, 4), (uint)Info.ImageBase);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x04, 4), (uint)Info.SizeOfImage);
                        BinaryPrimitives.WriteUInt32LittleEndian(Data.Slice(0x08, 4), (uint)Info.Flags);
                    }
                    else
                    {
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x00, 8), Info.ImageBase);
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x08, 8), Info.SizeOfImage);
                        BinaryPrimitives.WriteUInt64LittleEndian(Data.Slice(0x10, 8), Info.Flags);
                    }

                    if (!Instance.WriteMemory(MemoryInformation, Data.Slice(0, (int)RequiredLength)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                    Instance.TriggerEventMessage($"[-] NtQueryVirtualMemory was called with an unsupported class: 0x{MemoryInformationClass:X} ({MemoryInformationClass}).", LogFlags.Important);
            }
            return Instance.WinUnimplemented;
        }
    }
}