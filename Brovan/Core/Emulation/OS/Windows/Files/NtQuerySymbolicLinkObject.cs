using System.Reflection;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySymbolicLinkObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Is64 = Instance._binary.Architecture == BinaryArchitecture.x64;

            ulong LinkHandle = Instance.WinHelper.GetArg64(0);
            ulong LinkTargetPtr = Instance.WinHelper.GetArg64(1);
            ulong ReturnedLengthPtr = Instance.WinHelper.GetArg64(2);

            if (LinkHandle == 0 || LinkTargetPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            uint UsSize = Is64 ? 16u : 8u;
            if (!Instance.IsRegionMapped(LinkTargetPtr, UsSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (ReturnedLengthPtr != 0)
            {
                if (!Instance.IsRegionMapped(ReturnedLengthPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            IHandleObject Obj = Instance.WinHelper.HandleManager.GetObjectByHandle(LinkHandle);
            if (Obj == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            string Target = TryGetTargetString(Obj);
            if (Target == null)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            ushort MaximumLength = (ushort)(Instance.ReadMemoryUInt(LinkTargetPtr) >> 16);
            ulong Buffer = Is64 ? Instance.ReadMemoryULong(LinkTargetPtr + 0x8) : Instance.ReadMemoryUInt(LinkTargetPtr + 0x4);

            if (MaximumLength == 0)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            if (Buffer == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(Buffer, MaximumLength))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            uint RequiredBytes = (uint)(Target.Length * 2);

            if (ReturnedLengthPtr != 0)
                Instance._emulator.WriteMemory(ReturnedLengthPtr, RequiredBytes);

            Instance._emulator.WriteMemory(LinkTargetPtr + 0, (ushort)Math.Min(RequiredBytes, 0xFFFF), 2);

            if (MaximumLength < RequiredBytes)
                return NTSTATUS.STATUS_BUFFER_TOO_SMALL;

            Instance._emulator.WriteMemory(Buffer, Target, Encoding.Unicode);

            if (MaximumLength >= RequiredBytes + 2)
                Instance._emulator.WriteMemory(Buffer + RequiredBytes, (ushort)0, 2);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtQuerySymbolicLinkObject: Handle=0x{LinkHandle:X}, Target=\"{Target}\" (Len={RequiredBytes}).", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static string TryGetTargetString(IHandleObject Obj)
        {
            if (Obj is WinSymbolicLink Link)
                return Link.Target;
            return null;
        }
    }
}
