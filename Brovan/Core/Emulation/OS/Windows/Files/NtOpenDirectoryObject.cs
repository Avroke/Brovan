using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenDirectoryObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // Bitness-agnostic: args via GetArg64 (delegates to GetArg32 in WOW64); the OUT directory HANDLE is
            // pointer-sized; OBJECT_ATTRIBUTES has 4-byte fields on x86 / 8-byte on x64, so the name read branches.
            ulong DirectoryHandlePtr = Instance.WinHelper.GetArg64(0);
            AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

            if (DirectoryHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DirectoryHandlePtr, (ulong)Instance.GuestPointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string ObjectName;
            string FullName;
            NTSTATUS ObjectNameStatus;
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out ObjectName, out FullName, out ObjectNameStatus))
                    return ObjectNameStatus;
            }
            else
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName32((uint)ObjectAttributesPtr, out _, out _, out ObjectName, out FullName, out ObjectNameStatus))
                    return ObjectNameStatus;
            }

            if (string.IsNullOrEmpty(ObjectName))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            if (!Instance.WinHelper.TryGetKnownObjectDirectoryHandle(FullName, out ulong OutHandle))
            {
                if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                    Instance.TriggerEventMessage($"[!] NtOpenDirectoryObject: unsupported object directory \"{FullName}\" (Name=\"{ObjectName}\", DesiredAccess=0x{((ulong)DesiredAccess):X}).", LogFlags.Important);
                return NTSTATUS.STATUS_NOT_SUPPORTED;
            }

            if (!Instance.WritePointer(DirectoryHandlePtr, OutHandle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtOpenDirectoryObject: Name=\"{ObjectName}\", DesiredAccess=0x{((ulong)DesiredAccess):X}, Handle=0x{OutHandle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
