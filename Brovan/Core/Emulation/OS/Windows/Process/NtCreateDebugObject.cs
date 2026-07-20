using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtCreateDebugObject (SSN 0xA5 on 19041/19044). Creates a debug object and returns a
    /// handle. ntdll's DbgUiConnectToDbg calls it lazily when the debugging subsystem is
    /// first touched, so it is reached even without an actual debugger; creating a debug
    /// object is a normal, allowed operation and is not itself a debugger-presence signal
    /// (the "am I being debugged" answer is served by NtQueryInformationProcess
    /// ProcessDebugObjectHandle -> STATUS_PORT_NOT_SET). Returning a valid handle is the
    /// faithful result; leaving it STATUS_NOT_SUPPORTED is a tell.
    /// </summary>
    internal class NtCreateDebugObject : IWinSyscall
    {
        private const uint DebugKillOnClose = 0x1;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong DebugObjectHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributes = Instance.WinHelper.GetArg64(2);
            uint Flags = (uint)Instance.WinHelper.GetArg64(3);
            _ = ObjectAttributes;

            if (DebugObjectHandlePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((Flags & ~DebugKillOnClose) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(DebugObjectHandlePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint Id = Instance.WinHelper.GenerateRandomPID();
            WinDebugObject DebugObject = new WinDebugObject
            {
                Name = "DebugObject_" + Id.ToString(),
                KillOnClose = (Flags & DebugKillOnClose) != 0
            };

            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(DebugObject, (AccessMask)DesiredAccess);
            Instance.WinHelper.AddWinHandle(Handle);

            if (!Instance._emulator.WriteMemory(DebugObjectHandlePtr, Handle.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
