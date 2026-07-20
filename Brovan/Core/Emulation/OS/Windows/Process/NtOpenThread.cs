using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtOpenThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ThreadHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = Instance.WinHelper.GetArg64(1);
            ulong ClientIdPtr = Instance.WinHelper.GetArg64(3);

            if (ThreadHandlePtr == 0 || ClientIdPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong ThreadIdField = ClientIdPtr + (ulong)Instance.GuestPointerSize;
            ulong Tid = Instance.ReadPointer(ThreadIdField);
            EmulatedThread Thread = Instance.Threads.Values.FirstOrDefault(EmuThread => EmuThread.ThreadId == Tid);
            if (Thread == null)
                return NTSTATUS.STATUS_INVALID_CID;

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(Thread, (AccessMask)DesiredAccess);
            Instance.WinHelper.AddWinHandle(Handle);
            if (!Instance.WritePointer(ThreadHandlePtr, (ulong)Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}