using System;
using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// <c>NtOpenEvent(OUT PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)</c> — opens an existing named event.
    /// Sibling of <see cref="NtOpenMutant"/> / <see cref="NtOpenSemaphore"/>: consults <see cref="WinSysHelper.WinEvents"/>
    /// and returns <c>STATUS_OBJECT_NAME_NOT_FOUND</c> when the name isn't registered. Bitness-agnostic via
    /// <see cref="WinSysHelper.GetArg64"/> and <c>GuestPointerSize</c>-sized OUT handle. This SSN was
    /// unimplemented on WOW64 x86 — kernelbase's inter-process synchronisation helpers (notably combase's
    /// <c>CoInitializeSecurity</c> RPCSS handshake) were seeing <c>STATUS_NOT_SUPPORTED</c> instead of an
    /// honest name-not-found, driving them down error branches that expected the event API to at least be
    /// present.
    /// </summary>
    internal class NtOpenEvent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong EventHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

            if (EventHandlePtr == 0 || ObjectAttributesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(EventHandlePtr, (ulong)Instance.GuestPointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string FullName;
            NTSTATUS ObjectNameStatus;
            if (Instance.GuestPointerSize == 8)
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out _, out FullName, out ObjectNameStatus))
                    return ObjectNameStatus;
            }
            else
            {
                if (!Instance.WinHelper.TryReadObjectAttributesName32((uint)ObjectAttributesPtr, out _, out _, out _, out FullName, out ObjectNameStatus))
                    return ObjectNameStatus;
            }

            WinEvent Event = Instance.WinHelper.WinEvents.FirstOrDefault(e => e.Name != null && e.Name.Equals(FullName, StringComparison.OrdinalIgnoreCase));
            if (Event == null)
                return NTSTATUS.STATUS_OBJECT_NAME_NOT_FOUND;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Event, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance.WritePointer(EventHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
