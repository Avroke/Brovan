using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenSymbolicLinkObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            // Bitness-agnostic: args via GetArg64 (delegates to GetArg32 in WOW64); the OUT link HANDLE is
            // pointer-sized; OBJECT_ATTRIBUTES has 4-byte fields on x86 / 8-byte on x64, so the name read branches.
            ulong LinkHandlePtr = Instance.WinHelper.GetArg64(0);
            AccessMask DesiredAccess = (AccessMask)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

            if (LinkHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(LinkHandlePtr, (ulong)Instance.GuestPointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong RootDirectory;
            string Name;
            string FullName;
            NTSTATUS ObjectNameStatus;
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 Attributes, out Name, out FullName, out ObjectNameStatus))
                    return ObjectNameStatus;
                RootDirectory = Attributes.RootDirectory;
            }
            else
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName32((uint)ObjectAttributesPtr, out uint RootDirectory32, out _, out Name, out FullName, out ObjectNameStatus))
                    return ObjectNameStatus;
                RootDirectory = RootDirectory32;
            }

            if (string.IsNullOrEmpty(Name))
                return NTSTATUS.STATUS_OBJECT_NAME_INVALID;

            string Target = ResolveSymbolicLinkTarget(Instance, RootDirectory, Name, FullName);
            if (Target == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            WinSymbolicLink LinkObj = new WinSymbolicLink
            {
                FullName = FullName,
                Target = Target
            };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(LinkObj, DesiredAccess);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WritePointer(LinkHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtOpenSymbolicLinkObject: Name=\"{Name}\", FullName=\"{FullName}\", Target=\"{Target}\", Handle=0x{Handle.Handle:X}.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string ResolveSymbolicLinkTarget(BinaryEmulator Instance, ulong RootDirectory, string Name, string FullName)
        {
            if (RootDirectory == HandleManager.KNOWN_DLLS_DIRECTORY && Name.Equals("KnownDllPath", StringComparison.OrdinalIgnoreCase))
                return @"C:\Windows\System32";

            if (RootDirectory == HandleManager.KNOWN_DLLS32_DIRECTORY && Name.Equals("KnownDllPath", StringComparison.OrdinalIgnoreCase))
                return @"C:\Windows\SysWOW64";

            if (FullName.Equals("\\SystemRoot", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\HarddiskVolume1\\Windows";

            if (FullName.Equals("\\??\\SystemRoot", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\HarddiskVolume1\\Windows";

            if (FullName.Equals("\\??\\C:", StringComparison.OrdinalIgnoreCase) || FullName.Equals("\\DosDevices\\C:", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\HarddiskVolume1";

            if (FullName.Equals("\\??\\UNC", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\Mup";

            if (FullName.Equals("\\??\\PIPE", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\NamedPipe";

            if (FullName.Equals("\\??\\MAILSLOT", StringComparison.OrdinalIgnoreCase))
                return "\\Device\\Mailslot";

            return null;
        }
    }
}
