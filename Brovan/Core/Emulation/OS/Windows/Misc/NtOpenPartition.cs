using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtOpenPartition(PHANDLE PartitionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes).
    ///
    /// Opens a memory-partition object. ntdll's segment-heap initialisation (RtlpHpSegHeapCreate, reached from
    /// LdrpInitializeProcess) opens the process's partition during startup. Leaving this unimplemented returned
    /// STATUS_NOT_SUPPORTED, and although the ntdll caller tolerates the failure by branching around the
    /// partition-setup path, the process is then left without a partition and heap init aborts with
    /// STATUS_NO_MEMORY → STATUS_APP_INIT_FAILURE. Every process really does belong to a partition (the system
    /// partition is the implicit default), so the faithful behaviour is to hand back a valid handle.
    ///
    /// Bitness-agnostic: args via GetArg64 (delegates to GetArg32 in WOW64), OUT HANDLE is pointer-sized.
    /// </summary>
    internal class NtOpenPartition : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PartitionHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributes = Instance.WinHelper.GetArg64(2);

            if (PartitionHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(PartitionHandlePtr, (ulong)Instance.GuestPointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.CreatePartitionHandle(null, Permissions);
            if (!Instance.WritePointer(PartitionHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
