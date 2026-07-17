using System;
using Brovan;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // NtQueryFullAttributesFile(POBJECT_ATTRIBUTES, PFILE_NETWORK_OPEN_INFORMATION).
    // Sibling of NtQueryAttributesFile: same OBJECT_ATTRIBUTES-by-path probe, but the OUT
    // structure is FILE_NETWORK_OPEN_INFORMATION (adds AllocationSize + EndOfFile) instead of
    // FILE_BASIC_INFORMATION. kernelbase!GetFileAttributesExW routes through this syscall, so
    // its absence made GetFileAttributesExW fail on every path. That broke the .NET (Core)
    // apphost's pal::realpath (CreateFile-less path validation), which returned
    // CoreHostCurHostFindFailure (0x80008085) and printed "Failed to resolve full path of the
    // current executable" before ever loading hostfxr/coreclr.
    internal class NtQueryFullAttributesFile : IWinSyscall
    {
        // FILE_NETWORK_OPEN_INFORMATION is 0x38 on x64 (56 bytes).
        private const uint FileNetworkOpenInformationSize = 0x38;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(0);
            ulong FileInformationPtr = Instance.WinHelper.GetArg64(1);

            if (ObjectAttributesPtr == 0 || FileInformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileInformationPtr, FileNetworkOpenInformationSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out string Name, out string FullName, out NTSTATUS ObjectNameStatus))
                return ObjectNameStatus;

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string EmulatedPath = Instance.WinHelper.ResolveWindowsFilePath(FullName, Attributes.RootDirectory);
            if (string.IsNullOrEmpty(EmulatedPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            string HostPath = GeneralHelper.IO.ResolveHostPath(EmulatedPath, BinaryFormat.PE);
            if (string.IsNullOrEmpty(HostPath))
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            bool Exists = File.Exists(HostPath) || Directory.Exists(HostPath);
            if (!Exists)
            {
                if (!Instance.WinHelper.IsSyntheticDirectory(EmulatedPath))
                {
                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[!] NtQueryFullAttributesFile: file not found: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                    return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;
                }

                FillSyntheticDirectoryInformation(Instance, FileInformationPtr);
                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtQueryFullAttributesFile: Name=\"{Name}\", FullName=\"{FullName}\", SyntheticDir=\"{EmulatedPath}\".", LogFlags.Syscall);
                return NTSTATUS.STATUS_SUCCESS;
            }

            FillFileNetworkOpenInformation(Instance, FileInformationPtr, HostPath);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtQueryFullAttributesFile: Name=\"{Name}\", FullName=\"{FullName}\", HostPath=\"{HostPath}\".", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static void FillSyntheticDirectoryInformation(BinaryEmulator Instance, ulong FileInformationPtr)
        {
            long Now = Instance.GetEmulatedSystemTimeFileTimeUtc();
            Instance._emulator.WriteMemory(FileInformationPtr + 0x00, (ulong)Now, 8);   // CreationTime
            Instance._emulator.WriteMemory(FileInformationPtr + 0x08, (ulong)Now, 8);   // LastAccessTime
            Instance._emulator.WriteMemory(FileInformationPtr + 0x10, (ulong)Now, 8);   // LastWriteTime
            Instance._emulator.WriteMemory(FileInformationPtr + 0x18, (ulong)Now, 8);   // ChangeTime
            Instance._emulator.WriteMemory(FileInformationPtr + 0x20, 0UL, 8);          // AllocationSize
            Instance._emulator.WriteMemory(FileInformationPtr + 0x28, 0UL, 8);          // EndOfFile
            Instance._emulator.WriteMemory(FileInformationPtr + 0x30, (uint)FileAttributes.Directory, 4);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x34, 0u, 4);           // padding
        }

        private static void FillFileNetworkOpenInformation(BinaryEmulator Instance, ulong FileInformationPtr, string HostPath)
        {
            FileAttributes Attr;
            DateTime CreationUtc;
            DateTime LastAccessUtc;
            DateTime LastWriteUtc;
            long EndOfFile;

            if (Directory.Exists(HostPath))
            {
                DirectoryInfo di = new DirectoryInfo(HostPath);
                Attr = di.Attributes;
                CreationUtc = di.CreationTimeUtc;
                LastAccessUtc = di.LastAccessTimeUtc;
                LastWriteUtc = di.LastWriteTimeUtc;
                EndOfFile = 0;
            }
            else
            {
                FileInfo fi = new FileInfo(HostPath);
                Attr = fi.Attributes;
                CreationUtc = fi.CreationTimeUtc;
                LastAccessUtc = fi.LastAccessTimeUtc;
                LastWriteUtc = fi.LastWriteTimeUtc;
                EndOfFile = fi.Length;
            }

            // AllocationSize is the file size rounded up to the 4 KiB cluster, mirroring NTFS.
            long AllocationSize = EndOfFile <= 0 ? 0 : ((EndOfFile + 0xFFF) & ~0xFFFL);

            long CreationTime = CreationUtc.ToFileTimeUtc();
            long LastAccessTime = LastAccessUtc.ToFileTimeUtc();
            long LastWriteTime = LastWriteUtc.ToFileTimeUtc();
            long ChangeTime = LastWriteTime;

            Instance._emulator.WriteMemory(FileInformationPtr + 0x00, (ulong)CreationTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x08, (ulong)LastAccessTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x10, (ulong)LastWriteTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x18, (ulong)ChangeTime, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x20, (ulong)AllocationSize, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x28, (ulong)EndOfFile, 8);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x30, (uint)Attr, 4);
            Instance._emulator.WriteMemory(FileInformationPtr + 0x34, 0u, 4);
        }
    }
}
